"""Live Apache server-metrics dashboard.

Imported into a WSGIDaemonProcess group with threads=0 and
server-metrics=on. Polls the scoreboard once a second and
fans the snapshot out to any WebSocket clients.
"""

import asyncio
import json
import logging

import mod_wsgi
from aiohttp import WSMsgType, web

log = logging.getLogger("server-metrics-sidecar")

POLL_INTERVAL = 1.0

INDEX_HTML = """\
<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>mod_wsgi metrics</title></head>
<body>
<pre id="out">connecting...</pre>
<script>
  const base = window.METRICS_BASE || "";
  const proto = location.protocol === "https:" ? "wss" : "ws";
  const ws = new WebSocket(`${proto}://${location.host}${base}/ws`);
  const out = document.getElementById("out");
  ws.onopen = () => out.textContent = "connected";
  ws.onmessage = e => out.textContent = e.data;
  ws.onclose = () => out.textContent = "disconnected";
</script>
</body>
</html>
"""

async def index(request: web.Request) -> web.Response:
    # X-Forwarded-Prefix is set by mod_wsgi-express's
    # --proxy-mount-point, or by the equivalent RequestHeader
    # in raw Apache config. Inject it so the JS builds the
    # WebSocket URL with the right prefix when the sidecar is
    # mounted under a sub-URL.
    base = request.headers.get("X-Forwarded-Prefix", "").rstrip("/")
    inject = f'<script>window.METRICS_BASE = {json.dumps(base)};</script>\n'
    return web.Response(
        text=INDEX_HTML.replace("</head>", inject + "</head>", 1),
        content_type="text/html",
    )

async def ws_handler(request: web.Request) -> web.WebSocketResponse:
    ws = web.WebSocketResponse(heartbeat=30)
    await ws.prepare(request)
    request.app["clients"].add(ws)
    try:
        async for msg in ws:
            if msg.type == WSMsgType.ERROR:
                break
    finally:
        request.app["clients"].discard(ws)
    return ws

async def metrics_loop(app: web.Application) -> None:
    while True:
        snapshot = mod_wsgi.server_metrics()
        if snapshot is None:
            payload = json.dumps({
                "error": (
                    "scoreboard access is not enabled for this daemon "
                    "process group; set server-metrics=on on its "
                    "WSGIDaemonProcess directive (or pass "
                    "--server-metrics to mod_wsgi-express)"
                ),
            }, indent=2)
        else:
            payload = json.dumps({"snapshot": snapshot}, indent=2)
        for ws in list(app["clients"]):
            try:
                await ws.send_str(payload)
            except ConnectionResetError:
                pass
        await asyncio.sleep(POLL_INTERVAL)

async def serve() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )
    app = web.Application()
    app["clients"] = set()
    app.router.add_get("/", index)
    app.router.add_get("/ws", ws_handler)

    async def start_loop(_: web.Application) -> None:
        app["loop_task"] = asyncio.create_task(metrics_loop(app))
    app.on_startup.append(start_loop)

    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 8765)
    await site.start()
    log.info("server-metrics sidecar on 127.0.0.1:8765")
    await asyncio.Event().wait()

asyncio.run(serve())
