# mod_wsgi-telemetry

Source directory for the `mod_wsgi-telemetry` PyPi package: the
external telemetry ingester and live UI for the
[mod_wsgi](https://www.modwsgi.org) Apache module.

User-facing documentation lives on the mod_wsgi docs site, on the
**External Telemetry Service** page. That page covers what the
service is, how to enable it in Apache (both manually and via
`mod_wsgi-express`), how to run the ingester in production
including a systemd unit and socket-permission handling for
multi-user deployments, and the remote-access patterns (SSH
tunnel, Apache reverse proxy). Start there for setup:

  https://www.modwsgi.org

This README is for developers running the package from source,
debugging the wire format, exercising the UI without a running
mod_wsgi, or contributing changes.

## Running from source

The project is `uv`-managed:

```
cd telemetry
uv sync
uv run mod_wsgi-telemetry serve
```

That starts the ingester on `unix:/tmp/mod_wsgi-telemetry.sock`
and the UI on `http://127.0.0.1:8888/`. A bare
`mod_wsgi-telemetry` invocation defaults to `serve`; the four
subcommands are:

| Subcommand | Purpose |
|---|---|
| `serve` | Production ingester + HTTP/WebSocket UI. |
| `top` | Curses terminal monitor; connects to a running `serve` instance. |
| `dump` | Bind the listening socket directly and print decoded datagrams. |
| `simulate` | Send synthetic samples to a running ingester for UI development. |

`serve` and `top` are covered by the user guide; `dump` and
`simulate` are development tools and covered below.

## `dump`: inspect wire-format datagrams

`dump` confirms that the C side of mod_wsgi is emitting the binary
format the ingester expects. It binds the listening socket itself,
so do not run it alongside `serve`; the two would fight for the
socket. Each incoming datagram is printed as either pretty text or
one-line JSON.

```
uv run mod_wsgi-telemetry dump \
    --listen unix:/tmp/mod_wsgi-telemetry.sock
```

`--format json` is suited to piping into `jq` for filtering or
into a file for later inspection. `--count N` exits after N
samples so the command can be invoked from a script. The
`--socket-mode` and `--socket-group` options match those on
`serve` if `dump` is being used in a multi-user deployment.

## `simulate`: synthetic samples without mod_wsgi

`simulate` produces plausibly-shaped samples for a configurable
number of fake mod_wsgi processes, suitable for exercising the
ingester and UI without standing up a real Apache + mod_wsgi
environment. Slow-request records, lifecycle events, response
class breakdowns, and worker-slot busy fractions are all included
so every panel of the UI has data to show.

```
uv run mod_wsgi-telemetry serve &
uv run mod_wsgi-telemetry simulate \
    --target unix:/tmp/mod_wsgi-telemetry.sock \
    --processes 4 \
    --interval 1.0
```

Useful when iterating on the UI: changes to `static/index.html`
or the curses TUI can be exercised against a deterministic data
source without restarting Apache.

## Tests

```
cd telemetry
uv run pytest
```

The current tests cover the wire-format decoder (round-trip and
rejection cases). Higher-level integration tests covering the
ingester aggregation and WebSocket push surface are open work.

## Wire format

The decoder and field-ID table live in
[src/mod_wsgi_telemetry/wire.py](src/mod_wsgi_telemetry/wire.py).
This file mirrors `src/server/wsgi_telemetry.h` on the mod_wsgi C
side; the field IDs must stay in lockstep. Until the C header is
fully stable, both sides are maintained by hand. A codegen script
that regenerates the Python table from the C header is planned
but not yet written. Read the C header for the authoritative
field-ID enumeration.

Time-distribution histograms use an HDR-style layout: 16 octaves
from 1 ms to 65.5 s (powers of two), each octave linearly split
into 4 sub-buckets, plus one overflow bucket for values above
65.5 s, for 65 buckets per histogram. Maximum relative error
inside any sub-bucket is ≤25%. The encoder in
`wsgi_record_time_in_buckets` indexes via `frexp` in O(1).

Min/max are skipped on idle ticks (the C-side accumulators carry
a `UINT64_MAX` sentinel until at least one request lands in the
tick), so absence of the field on the wire is interpreted as "no
data this tick". Both aggregate cleanly across processes
(min-of-mins, max-of-maxes) and across time windows; pair them
with the bucket-derived percentiles to read true worst-case
alongside the shape of the distribution.

## Layout

```
src/mod_wsgi_telemetry/
    cli.py         Top-level subcommand dispatcher
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

## Troubleshooting (development)

Operational troubleshooting (UI shows `disconnected`, samples
have `request_count=0`, etc.) is covered on the user guide page.
A few problems that mostly arise during development:

- **`bind: address already in use`.** A previous run did not clean
  up its socket file, or `dump` and `serve` are running against the
  same path. Stop the other process; the next run unlinks the stale
  file before bind.
- **UI loads but charts are empty.** The WebSocket is connected
  (no `disconnected` banner) but no samples are arriving. Run
  `simulate` against the same socket to confirm the UI side
  works, then point at the real mod_wsgi-side socket to isolate
  the gap.
- **`decode_errors` climbing.** Wire-format mismatch. Likely a
  field ID added on the C side without the matching entry in
  `wire.py`. Cross-check `src/server/wsgi_telemetry.h` against
  `wire.py`.

## Contributing

Bug reports, design discussion, and pull requests live at
[https://github.com/GrahamDumpleton/mod_wsgi](https://github.com/GrahamDumpleton/mod_wsgi).
The `mod_wsgi-telemetry` package is developed inside the same
repository as the `mod_wsgi` Apache module so that wire-format
changes on both sides can land in the same commit.
