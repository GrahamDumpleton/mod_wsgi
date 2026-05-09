"""HTTP + WebSocket server that exposes the ingester's state.

Routes:
    GET /              static UI
    GET /static/*      static assets
    GET /ws            WebSocket push of new samples; initial message is a
                       snapshot of the rolling window so reloads don't lose
                       historical context.
    GET /api/state     JSON rendering of the rolling window (debugging aid).
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import signal
import sys
from pathlib import Path

from aiohttp import WSMsgType, web

from .ingest import Ingester

log = logging.getLogger(__name__)

STATIC_DIR = Path(__file__).parent / "static"


async def index(request: web.Request) -> web.Response:
    # Explicit --root-path wins; otherwise honour X-Forwarded-Prefix from
    # the request, which mod_wsgi-express sets automatically for any
    # mount-point proxy. With neither, base is empty and the JS builds
    # root-anchored URLs (correct for direct access).
    base = request.app["root_path"]
    if not base:
        base = _normalize_root_path(
            request.headers.get("X-Forwarded-Prefix", ""))
    inject = f"<script>window.TELEMETRY_BASE = {json.dumps(base)};</script>\n"
    html = request.app["index_html_raw"].replace(
        "</head>", inject + "</head>", 1)
    return web.Response(text=html, content_type="text/html")


def _normalize_root_path(value: str) -> str:
    # "" / "/" mean no prefix; otherwise enforce one leading slash and no
    # trailing slash so concatenation in the JS (`${BASE}/ws`) is safe.
    value = value.strip()
    if not value or value == "/":
        return ""
    if not value.startswith("/"):
        value = "/" + value
    return value.rstrip("/")


async def api_state(request: web.Request) -> web.Response:
    ingester: Ingester = request.app["ingester"]
    return web.json_response(ingester.snapshot())


async def api_slow_clear(request: web.Request) -> web.Response:
    ingester: Ingester = request.app["ingester"]
    ingester.clear_slow_requests()
    return web.json_response({"ok": True})


async def websocket(request: web.Request) -> web.WebSocketResponse:
    ingester: Ingester = request.app["ingester"]
    ws = web.WebSocketResponse(heartbeat=30)
    await ws.prepare(request)

    websockets: set[web.WebSocketResponse] = request.app["websockets"]
    websockets.add(ws)
    q = ingester.subscribe()
    try:
        await ws.send_json(ingester.snapshot())

        async def reader() -> None:
            # Drains incoming frames; exits when the client closes
            # the connection, errors, or the server calls ws.close()
            # from close_websockets during shutdown. Reaching the
            # end of this coroutine is the signal the writer loop
            # below uses to know the ws is going away.
            async for msg in ws:
                if msg.type == WSMsgType.ERROR:
                    log.warning("ws client error: %s", ws.exception())
                    break

        reader_task = asyncio.create_task(reader())

        # Writer loop: race each q.get() against the reader exiting
        # so a shutdown (or client disconnect) wakes the writer
        # immediately rather than waiting for the queue to produce
        # something. Previously this loop polled q.get() on a 30 s
        # timeout, which delayed server shutdown by up to that long
        # whenever no metrics were arriving.
        while not ws.closed:
            get_task = asyncio.create_task(q.get())
            done, _ = await asyncio.wait(
                {get_task, reader_task},
                return_when=asyncio.FIRST_COMPLETED,
            )
            if reader_task in done:
                get_task.cancel()
                try:
                    await get_task
                except (asyncio.CancelledError, Exception):
                    pass
                break
            payload = get_task.result()
            try:
                await ws.send_json(payload)
            except ConnectionResetError:
                break

        if not reader_task.done():
            reader_task.cancel()
            try:
                await reader_task
            except (asyncio.CancelledError, Exception):
                pass
    finally:
        websockets.discard(ws)
        ingester.unsubscribe(q)
        if not ws.closed:
            await ws.close()

    return ws


async def build_app(listen_spec: str, root_path: str = "") -> web.Application:
    ingester = Ingester(listen_spec)
    app = web.Application()
    app["ingester"] = ingester
    app["websockets"] = set()
    app["root_path"] = root_path
    app["index_html_raw"] = (STATIC_DIR / "index.html").read_text(
        encoding="utf-8")
    app.router.add_get("/", index)
    app.router.add_get("/ws", websocket)
    app.router.add_get("/api/state", api_state)
    app.router.add_post("/api/slow/clear", api_slow_clear)
    app.router.add_static("/static/", STATIC_DIR)

    async def start_ingester(_: web.Application) -> None:
        app["ingester_task"] = asyncio.create_task(ingester.run())

    async def close_websockets(_: web.Application) -> None:
        for ws in list(app["websockets"]):
            await ws.close(code=1001, message=b"server shutdown")

    async def stop_ingester(_: web.Application) -> None:
        task: asyncio.Task = app["ingester_task"]
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

    app.on_startup.append(start_ingester)
    app.on_shutdown.append(close_websockets)
    app.on_cleanup.append(stop_ingester)
    return app


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="mod_wsgi telemetry ingester + live UI."
    )
    ap.add_argument("--listen", default="unix:/tmp/mod_wsgi-telemetry.sock",
                    help="unix:/path/to/sock  (default: %(default)s)")
    ap.add_argument("--http-host", default="127.0.0.1")
    ap.add_argument("--http-port", type=int, default=8877)
    ap.add_argument("--root-path", default="",
                    help="URL prefix when fronted by a reverse proxy that "
                         "strips it (e.g. /ui). Used to build links and the "
                         "WebSocket URL in the served HTML. The proxy must "
                         "strip the prefix before the request reaches this "
                         "server. When unset, the X-Forwarded-Prefix request "
                         "header is honoured if present (mod_wsgi-express's "
                         "--proxy-mount-point sets it automatically).")
    ap.add_argument("--log-level", default="INFO")
    args = ap.parse_args(argv)
    root_path = _normalize_root_path(args.root_path)

    logging.basicConfig(
        level=args.log_level.upper(),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )

    async def run() -> None:
        app = await build_app(args.listen, root_path)
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, args.http_host, args.http_port)
        await site.start()
        log.info("UI on http://%s:%d/ (root-path=%r)",
                 args.http_host, args.http_port, root_path)

        loop = asyncio.get_running_loop()
        stop = loop.create_future()

        def request_stop(sig: int) -> None:
            if not stop.done():
                log.info("received %s, shutting down", signal.Signals(sig).name)
                stop.set_result(None)

        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(sig, request_stop, sig)
            except NotImplementedError:
                signal.signal(sig, lambda s, _f: request_stop(s))

        try:
            await stop
        finally:
            await runner.cleanup()

    asyncio.run(run())
    return 0


if __name__ == "__main__":
    sys.exit(main())
