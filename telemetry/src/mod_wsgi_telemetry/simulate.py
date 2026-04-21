"""Emit synthetic telemetry samples so the ingester and UI can be tested
without a running mod_wsgi.

Produces plausibly-shaped request_metrics samples for N fake processes,
one per interval. Values oscillate over time so charts show movement.

Usage:
    mod-wsgi-telemetry-simulate \\
        --target unix:/tmp/mod_wsgi-telemetry.sock \\
        --processes 4 --interval 1.0
"""

from __future__ import annotations

import argparse
import math
import os
import random
import socket
import sys
import time

from .wire import KIND_REQUEST, Sample, encode


def parse_target(spec: str) -> tuple[int, tuple]:
    """Return (family, addr) for socket.sendto."""
    if spec.startswith("unix:"):
        return socket.AF_UNIX, spec[len("unix:"):]
    if spec.startswith("udp:"):
        rest = spec[len("udp:"):]
        host, _, port = rest.rpartition(":")
        if not host or not port:
            raise ValueError(f"bad udp target {spec!r}")
        return socket.AF_INET, (host, int(port))
    raise ValueError(f"unknown scheme in target {spec!r}: expected unix: or udp:")


def make_sample(pid: int, seq: int, phase: float, interval: float) -> Sample:
    """Build one synthetic request_metrics sample."""
    base = 100 + 60 * math.sin(phase)
    jitter = random.uniform(-10, 10)
    throughput = max(0.0, base + jitter)
    cap = min(1.0, throughput / 200.0)
    cpu_user = cap * random.uniform(0.35, 0.55)
    cpu_sys = cap * random.uniform(0.05, 0.12)

    count = int(throughput * interval)
    app_time = 0.02 + 0.05 * cap + random.uniform(-0.003, 0.003)
    srv_time = app_time + random.uniform(0.001, 0.004)

    def bucketise(total: int, concentration: int) -> list[int]:
        buckets = [0] * 16
        for _ in range(total):
            idx = max(0, min(15, int(random.gauss(concentration, 1.5))))
            buckets[idx] += 1
        return buckets

    rss = 120 * 1024 * 1024 + int(10 * 1024 * 1024 * math.sin(phase / 3))

    fields = {
        "hostname": socket.gethostname(),
        "process_group": "simulated",
        "sample_period": float(interval),
        "request_count": count,
        "request_throughput": throughput,
        "capacity_utilization": cap,
        "cpu_user_utilization": cpu_user,
        "cpu_system_utilization": cpu_sys,
        "cpu_utilization": cpu_user + cpu_sys,
        "memory_rss": rss,
        "memory_max_rss": rss + 8 * 1024 * 1024,
        "request_threads_maximum": 5,
        "request_threads_active": max(1, min(5, int(cap * 5 + 1))),
        "server_time": srv_time,
        "queue_time": random.uniform(0.0005, 0.003),
        "daemon_time": random.uniform(0.0005, 0.002),
        "application_time": app_time,
        "application_time_buckets": bucketise(count, concentration=6),
        "server_time_buckets": bucketise(count, concentration=7),
        "input_bytes_total": count * 256,
        "output_bytes_total": count * 1024,
        "slow_requests": random.randint(0, max(0, count // 50)),
        "aborted_requests": random.randint(0, max(0, count // 200)),
    }

    return Sample(
        version=1,
        kind=KIND_REQUEST,
        pid=pid,
        seq=seq,
        stamp_us=int(time.time() * 1_000_000),
        fields=fields,
    )


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--target", required=True,
                    help="unix:/path/to/sock  or  udp:host:port")
    ap.add_argument("--processes", type=int, default=4)
    ap.add_argument("--interval", type=float, default=1.0)
    ap.add_argument("--duration", type=float, default=0.0,
                    help="stop after N seconds (0 = forever)")
    args = ap.parse_args(argv)

    family, addr = parse_target(args.target)
    sock = socket.socket(family, socket.SOCK_DGRAM)

    pids = [100000 + i for i in range(args.processes)]
    seqs = [0] * args.processes
    phases = [random.uniform(0, 2 * math.pi) for _ in range(args.processes)]

    start = time.monotonic()
    sent = 0
    try:
        while True:
            if args.duration and time.monotonic() - start > args.duration:
                break
            for i in range(args.processes):
                phases[i] += args.interval / 15.0
                seqs[i] += 1
                sample = make_sample(pids[i], seqs[i], phases[i], args.interval)
                try:
                    sock.sendto(encode(sample), addr)
                    sent += 1
                except OSError as e:
                    print(f"sendto failed: {e}", file=sys.stderr)
            time.sleep(args.interval)
    except KeyboardInterrupt:
        pass
    finally:
        sock.close()

    print(f"sent {sent} samples")
    return 0


if __name__ == "__main__":
    sys.exit(main())
