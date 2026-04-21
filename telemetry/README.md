# mod_wsgi telemetry — ingester and live UI

Ingestion service and browser-based live view for telemetry samples
emitted by mod_wsgi's telemetry reporter thread. Python POC; will be
ported to Go once the wire format and UI are proven.

## Quick start — with a real mod_wsgi server

```
# Terminal 1 — start the ingester + UI
cd telemetry
uv sync
uv run mod-wsgi-telemetry
# → Listens on unix:/tmp/mod_wsgi-telemetry.sock
# → UI on http://127.0.0.1:8877

# Terminal 2 — run mod_wsgi-express with telemetry reporter enabled
#   (from the mod_wsgi project root)
mod_wsgi-express start-server tests/hello.wsgi \
    --port 8080 \
    --processes 2 --threads 3 \
    --telemetry-target unix:/tmp/mod_wsgi-telemetry.sock \
    --telemetry-interval 1.0

# Terminal 3 — drive some traffic
while true; do curl -s http://localhost:8080/ > /dev/null; done

# Browser → http://127.0.0.1:8877
```

Each mod_wsgi daemon process runs a background thread that sends a
binary TLV datagram every `--telemetry-interval` seconds. The ingester
decodes, aggregates by PID, and pushes samples over WebSocket to any
connected UI clients.

## Quick start — without mod_wsgi (simulated samples)

Useful when you're hacking on the UI or the decoder and don't want to
stand up a full mod_wsgi-express environment.

```
cd telemetry
uv sync

# Terminal 1 — ingester + UI
uv run mod-wsgi-telemetry

# Terminal 2 — synthetic samples
uv run mod-wsgi-telemetry-simulate \
    --target unix:/tmp/mod_wsgi-telemetry.sock \
    --processes 4
```

## Remote ingester (UDP)

```
# On the metrics host
uv run mod-wsgi-telemetry --listen udp:0.0.0.0:9876

# On each mod_wsgi host
mod_wsgi-express start-server app.wsgi \
    --telemetry-target udp:metrics.internal:9876
```

UDP is cleartext; use only over trusted networks or via a tunnel. The
default path-MTU ceiling is the practical upper bound on message size
(roughly 1500 bytes on Ethernet). A request_metrics sample is ~400
bytes; that's safely below the ceiling.

## Commands

| Command | Purpose |
|---|---|
| `mod-wsgi-telemetry` | HTTP + WebSocket server, spawns the datagram receiver. `--listen unix:/path` or `--listen udp:host:port`. UI on `--http-host` / `--http-port` (default 127.0.0.1:8877). |
| `mod-wsgi-telemetry-dump` | CLI alternative that binds the socket itself and prints decoded samples. Don't run alongside the server — they'd fight for the socket. Useful when iterating on the wire format. |
| `mod-wsgi-telemetry-simulate` | Emits synthetic samples so the UI can be exercised without a running mod_wsgi. |

## Ports and sockets

By default the ingester uses:

- `unix:/tmp/mod_wsgi-telemetry.sock` for incoming telemetry datagrams.
- `127.0.0.1:8877` for the HTTP UI and WebSocket.

The UI port was deliberately picked to avoid the default
`scripts/run-benchmark.sh` port (8765) — the benchmark cleanup
historically force-killed anything bound to its port and would take the
UI down with it. If you run multiple ingesters, or you already have
something on 8877, override with `--http-port`:

```
uv run mod-wsgi-telemetry --http-port 9080
```

Likewise if two deployments want separate telemetry streams, give each
its own socket path:

```
uv run mod-wsgi-telemetry --listen unix:/tmp/mod_wsgi-telemetry-staging.sock
```

and point `mod_wsgi-express --telemetry-target` at the matching path.

## mod_wsgi-express options

| Option | Description |
|---|---|
| `--telemetry-target TARGET` | Enable the telemetry reporter. `unix:/path` for a local datagram socket or `udp:host:port` for a remote ingester. Off by default. |
| `--telemetry-interval SECONDS` | Sampling interval (default `1.0`). Floor of 0.1s enforced in C. |

Under the hood these translate to the `WSGITelemetryReporter` Apache
directive in the generated `httpd.conf`. Equivalent manual form:

```apache
WSGITelemetryReporter unix:/tmp/mod_wsgi-telemetry.sock interval=1.0
```

Only activated in daemon-mode processes today. Embedded-mode support is
a future extension.

## Wire format

The decoder and field-ID table live in
[src/mod_wsgi_telemetry/wire.py](src/mod_wsgi_telemetry/wire.py). This
file mirrors `src/server/wsgi_telemetry.h` on the mod_wsgi C side —
keep the field IDs in lockstep. Once the C header is stable, a small
codegen script should regenerate the Python table from it; for now
both sides are maintained by hand.

## Tests

```
uv run pytest
```

## Layout

```
src/mod_wsgi_telemetry/
    wire.py        TLV decoder + field table (mirrors wsgi_telemetry.h)
    ingest.py      Async datagram receiver + rolling per-PID window
    server.py      aiohttp HTTP + WebSocket + static handler
    dump.py        CLI decoded-sample printer
    simulate.py    Synthetic sample emitter
    static/
        index.html Single-page UI (vanilla JS canvas charts)
tests/
    test_wire.py   Round-trip + rejection tests for the decoder
```

## Troubleshooting

- **UI shows `disconnected`.** The WebSocket couldn't reach the server.
  Check the ingester is still running and `--http-port` matches.
- **UI connected but no data.** mod_wsgi may not be reaching the
  socket — check that `--telemetry-target` on both sides matches
  exactly, and that the Apache user has permission to open the socket
  path. The ingester log prints `listening on ...` at startup.
- **`decode_errors` climbing.** Version mismatch or corruption. Stop
  the ingester and mod_wsgi, verify both were built from the same
  tree, and restart.
- **Samples have `request_count=0` after traffic.** Load may have
  completed within a single sample window before the next tick. Try
  `--telemetry-interval 0.5` for finer resolution during testing.
