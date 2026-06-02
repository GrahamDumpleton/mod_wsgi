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


def _parse_octal_mode(s: str) -> int:
    try:
        return int(s, 8)
    except ValueError:
        raise argparse.ArgumentTypeError(
            f"socket-mode must be octal (e.g. 0660 or 660), got {s!r}")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--listen", default="unix:/tmp/mod_wsgi-telemetry.sock")
    ap.add_argument("--socket-mode", type=_parse_octal_mode, default=0o660,
                    metavar="MODE",
                    help="Octal permission mode for the UNIX socket "
                         "(default: 0660).")
    ap.add_argument("--socket-group", default=None, metavar="GROUP",
                    help="Group name or numeric GID to chown the UNIX "
                         "socket to.")
    ap.add_argument("--format", choices=["text", "json"], default="text")
    ap.add_argument("--count", type=int, default=0,
                    help="stop after N samples (0 = forever)")
    args = ap.parse_args(argv)

    socket_group: str | int | None = args.socket_group
    if isinstance(socket_group, str) and socket_group.isdigit():
        socket_group = int(socket_group)

    sock = open_socket(args.listen, mode=args.socket_mode, group=socket_group)
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
