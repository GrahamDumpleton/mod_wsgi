# mod_wsgi telemetry — ingester and live UI

Ingestion service and browser-based live view for telemetry samples
emitted by mod_wsgi's telemetry reporter thread. Python POC; will be
ported to Go once the wire format and UI are proven.

## Quick start — with a real mod_wsgi server

```
# Terminal 1 — start the ingester + UI
cd telemetry
uv sync
uv run mod_wsgi-telemetry serve
# → Listens on unix:/tmp/mod_wsgi-telemetry.sock
# → UI on http://127.0.0.1:8877

# Terminal 2 — run mod_wsgi-express with telemetry reporter enabled
#   (from the mod_wsgi project root)
mod_wsgi-express start-server tests/hello.wsgi \
    --port 8080 \
    --processes 2 --threads 3 \
    --telemetry-service unix:/tmp/mod_wsgi-telemetry.sock \
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
uv run mod_wsgi-telemetry serve

# Terminal 2 — synthetic samples
uv run mod_wsgi-telemetry simulate \
    --target unix:/tmp/mod_wsgi-telemetry.sock \
    --processes 4
```

## Terminal monitor (`top`-style)

`mod_wsgi-telemetry top` is a curses-based live monitor for the same
data the browser UI shows. It connects to a running ingester over the
existing WebSocket, so it runs alongside (not instead of) the browser
UI — open as many TUI clients as you like.

```
# Terminal 1 — ingester + UI as before
uv run mod_wsgi-telemetry serve

# Terminal 2 — terminal monitor
uv run mod_wsgi-telemetry top
# → connects to ws://127.0.0.1:8877/ws by default
```

Layout: an eight-line header stays visible across all views —
hostname/group title bar, throughput, capacity bar, CPU + memory,
HTTP response class breakdown (`1xx / 2xx / 3xx / 4xx / 5xx`),
latency `p50 / p95 / p99` + min/max, slow-request counters, and
the tab bar. The body switches with one keystroke:

| Key | View | Body |
|---|---|---|
| `o` / `1` | overview | sparklines for RPS, capacity, CPU, RSS + per-phase mean times |
| `p` / `2` | processes | per-PID table sortable by RPS, CPU, RSS, p95, slow count, PID |
| `w` / `3` | workers | per-PID slot grid (`.` idle · `*` <1s · `#` 1-5s · `!` ≥ slow threshold) |
| `l` / `4` | latency | ASCII HDR histogram for the chosen phase + p50/p95/p99 markers |
| `s` / `5` | slow | live slow-request list with sort, state filter, URL search |

Common keys: `space` pause/resume, `+` / `-` refresh rate, `<` / `>`
sort or window, `[` / `]` cycle phase (latency view), `f` cycle
filters (process group, or slow-state in slow view), `/` URL search
(slow view; Enter applies, Esc clears), `r` reset slow filters, `?`
help overlay, `q` quit.

Useful options:

```
mod_wsgi-telemetry top --url ws://host:8877/ws    # connect to a different host
mod_wsgi-telemetry top --view slow                # start on the slow-requests view
mod_wsgi-telemetry top --group app1               # filter to one process group
mod_wsgi-telemetry top --once                     # one-shot status to stdout, no curses
```

`--once` writes a plain-text snapshot of the header + process table
and exits, so the monitor doubles as a scriptable status reporter for
shell pipelines, cron healthchecks, or CI assertions. Exit code is `0`
if a snapshot was received, `2` if the timeout elapsed without one.

## Transport

The reporter and the ingester only support UNIX SOCK_DGRAM. The
ingester is intended to run co-located with the mod_wsgi processes,
which removes IP-fragmentation, MTU sizing and packet loss from the
list of things to worry about. As a result, per-tick datagrams are
allowed to grow well past the Ethernet MTU (peak ~4.4 KB at 128
worker slots; the C-side stack buffer is sized at 8 KB).

Earlier `udp:host:port` targets are no longer accepted on either side
— `WSGITelemetryService udp:...` and `--telemetry-service udp:...` will be
rejected at config-parse time with a clear error, and the ingester's
`--listen` only accepts `unix:/path`. Use a tunnelled file-system
mount (e.g. shared NFS path) or a sidecar relay if you genuinely need
to ship telemetry across hosts.

## Commands

| Command | Purpose |
|---|---|
| `mod_wsgi-telemetry serve` | HTTP + WebSocket server, spawns the datagram receiver. `--listen unix:/path` (UNIX SOCK_DGRAM only). UI on `--http-host` / `--http-port` (default 127.0.0.1:8877). |
| `mod_wsgi-telemetry top` | Curses terminal monitor. Connects to a running server's WebSocket and renders the same data as the browser UI in five keystroke-switchable views. `--once` for a scriptable plain-text snapshot. |
| `mod_wsgi-telemetry dump` | CLI alternative that binds the socket itself and prints decoded samples. Don't run alongside the server — they'd fight for the socket. Useful when iterating on the wire format. |
| `mod_wsgi-telemetry simulate` | Emits synthetic samples so the UI can be exercised without a running mod_wsgi. |

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
uv run mod_wsgi-telemetry serve --http-port 9080
```

Likewise if two deployments want separate telemetry streams, give each
its own socket path:

```
uv run mod_wsgi-telemetry serve --listen unix:/tmp/mod_wsgi-telemetry-staging.sock
```

and point `mod_wsgi-express --telemetry-service` at the matching path.

## mod_wsgi-express options

| Option | Description |
|---|---|
| `--telemetry-service TARGET` | Enable the telemetry reporter. `unix:/path` for a local datagram socket. Remote `udp:host:port` targets are not supported. Off by default. |
| `--telemetry-interval SECONDS` | Sampling interval (default `1.0`). Floor of 0.1s enforced in C. |

Under the hood these translate to the `WSGITelemetryService` Apache
directive in the generated `httpd.conf`. Equivalent manual form:

```apache
WSGITelemetryService unix:/tmp/mod_wsgi-telemetry.sock interval=1.0
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

Per-phase data (server, queue, daemon, application, request) is
grouped into contiguous 10-wide field-ID blocks of five entries each
so the layout stays symmetric as new per-phase signals are added:

| Range | Block |
|---|---|
| 60-69 | per-phase mean times (seconds, f64) |
| 70-79 | per-phase exact min times (microseconds, u64) |
| 80-89 | per-phase exact max times (microseconds, u64) |
| 90-99 | per-phase histograms (i32 array) |

Time-distribution histograms use an HDR-style layout: 16 octaves from
1 ms to 65.5 s (powers of two), each octave linearly split into 4
sub-buckets, plus one overflow bucket for >65.5 s — 65 entries per
phase. Maximum relative error inside any sub-bucket is ≤25%. The
encoder in `wsgi_record_time_in_buckets` indexes via `frexp` in O(1).

Min/max are skipped on idle ticks (the C-side accumulators carry a
`UINT64_MAX` sentinel until at least one request lands in the tick),
so absence of the field on the wire is interpreted as "no data this
tick". Both aggregate cleanly across processes (min-of-mins,
max-of-maxes) and across time windows; pair them with the
bucket-derived percentiles to read true worst-case alongside the
shape of the distribution.

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
    tui.py         Curses terminal monitor (WebSocket client of server.py)
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
  socket — check that `--telemetry-service` on the mod_wsgi side and
  `--listen` on the ingester point at the same `unix:` path, and that
  the Apache user has permission to open the socket path. The
  ingester log prints `listening on ...` at startup.
- **`decode_errors` climbing.** Version mismatch or corruption. Stop
  the ingester and mod_wsgi, verify both were built from the same
  tree, and restart.
- **Samples have `request_count=0` after traffic.** Load may have
  completed within a single sample window before the next tick. Try
  `--telemetry-interval 0.5` for finer resolution during testing.
