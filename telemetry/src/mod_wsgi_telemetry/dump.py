"""CLI pretty-printer for the telemetry wire format.

Binds the listening socket itself (so don't run this at the same time as
the ingester), receives datagrams, decodes, prints.

Usage:
    mod_wsgi-telemetry dump --listen unix:/tmp/mod_wsgi-telemetry.sock
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import sys
from datetime import datetime, timezone

from .ingest import open_socket
from .wire import decode


def _fmt_value(v):
    if isinstance(v, bytes):
        try:
            return v.decode("utf-8")
        except UnicodeDecodeError:
            return v.hex()
    return v


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--listen", default="unix:/tmp/mod_wsgi-telemetry.sock")
    ap.add_argument("--format", choices=["text", "json"], default="text")
    ap.add_argument("--count", type=int, default=0,
                    help="stop after N samples (0 = forever)")
    args = ap.parse_args(argv)

    sock = open_socket(args.listen)
    sock.setblocking(True)
    seen = 0
    try:
        while True:
            data, _ = sock.recvfrom(65536)
            try:
                sample = decode(data)
            except Exception as e:
                print(f"decode error: {e} (len={len(data)})", file=sys.stderr)
                continue

            if args.format == "json":
                payload = {
                    "kind": sample.kind_name,
                    "pid": sample.pid,
                    "seq": sample.seq,
                    "stamp": sample.stamp,
                    "fields": {k: _fmt_value(v) for k, v in sample.fields.items()},
                }
                print(json.dumps(payload))
            else:
                ts = datetime.fromtimestamp(
                    sample.stamp, tz=timezone.utc
                ).isoformat(timespec="milliseconds")
                print(
                    f"\n[{ts}] pid={sample.pid} seq={sample.seq} "
                    f"kind={sample.kind_name} v{sample.version}"
                )
                for k, v in sample.fields.items():
                    print(f"  {k:30s} = {_fmt_value(v)}")

            seen += 1
            if args.count and seen >= args.count:
                break
    except KeyboardInterrupt:
        pass
    finally:
        sock.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
