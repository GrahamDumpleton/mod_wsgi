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

from .wire import KIND_REQUEST, KIND_SLOW_REQUEST, Sample, encode


# Handler paths the simulator cycles through so the Slow Requests tab
# shows variety. Includes one with a URL long enough to exercise the
# ellipsis-truncation path in the UI.
_SLOW_PATHS = [
    ("GET",  "/api/reports/render"),
    ("POST", "/api/orders/checkout"),
    ("GET",  "/admin/users/export"),
    ("POST", "/api/image/thumbnail"),
    ("GET",  "/api/search/" + "aaa/" * 60 + "end"),
]


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


_SLOT_COUNT = 5


def make_sample(pid: int, seq: int, phase: float, interval: float,
                slot_state: dict | None = None) -> Sample:
    """Build one synthetic request_metrics sample.

    slot_state is a per-process dict carrying stateful slot info across
    ticks: which slot (if any) is currently "stuck" on a long request,
    and how long it's been stuck. Mutated in place.
    """
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

    # Per-slot capacity arrays. Each slot's base busy-fraction is a
    # blend of the process-wide capacity and per-slot jitter, so slots
    # diverge visibly on the heatmap even when the process average is
    # steady. One slot may be "stuck" on a long request — its
    # current_elapsed climbs across ticks and its busy-time saturates.
    if slot_state is None:
        slot_state = {}

    # Randomly start or release a stuck slot so the UI shows activity.
    stuck_slot = slot_state.get("stuck_slot")
    stuck_since_ms = slot_state.get("stuck_since_ms", 0)
    if stuck_slot is None:
        if cap > 0.4 and random.random() < 0.05:
            stuck_slot = random.randrange(_SLOT_COUNT)
            stuck_since_ms = 0
    else:
        stuck_since_ms += int(interval * 1000)
        if stuck_since_ms > 15000 or random.random() < 0.08:
            stuck_slot = None
            stuck_since_ms = 0
    slot_state["stuck_slot"] = stuck_slot
    slot_state["stuck_since_ms"] = stuck_since_ms

    sample_period_us = int(interval * 1_000_000)
    slot_request_count = [0] * _SLOT_COUNT
    slot_busy_time_us = [0] * _SLOT_COUNT
    slot_cpu_time_us = [0] * _SLOT_COUNT
    slot_current_elapsed_ms = [0] * _SLOT_COUNT
    slot_max_duration_ms = [0] * _SLOT_COUNT

    for s in range(_SLOT_COUNT):
        if s == stuck_slot:
            # Pinned on a long request — busy near 100%, no completions,
            # current_elapsed climbing.
            slot_busy_time_us[s] = int(sample_period_us * random.uniform(0.92, 1.0))
            slot_cpu_time_us[s] = int(slot_busy_time_us[s] * random.uniform(0.05, 0.25))
            slot_current_elapsed_ms[s] = stuck_since_ms
            slot_max_duration_ms[s] = stuck_since_ms
            slot_request_count[s] = 0
        else:
            slot_cap = max(0.0, min(1.0, cap + random.uniform(-0.25, 0.25)))
            slot_busy_time_us[s] = int(sample_period_us * slot_cap)
            cpu_frac = random.uniform(0.3, 0.8)
            slot_cpu_time_us[s] = int(slot_busy_time_us[s] * cpu_frac)
            slot_request_count[s] = max(
                0, int(slot_cap * count / max(1, _SLOT_COUNT - (1 if stuck_slot is not None else 0))
                       + random.uniform(-2, 2)))
            # Heavy-tailed max-duration per tick.
            if slot_request_count[s] > 0:
                slot_max_duration_ms[s] = int(
                    max(5, random.lognormvariate(3.5, 0.8))
                )

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
        "request_threads_maximum": _SLOT_COUNT,
        "request_threads_active": max(1, min(_SLOT_COUNT,
                                             sum(1 for v in slot_busy_time_us
                                                 if v > 0))),
        "server_time": srv_time,
        "queue_time": random.uniform(0.0005, 0.003),
        "daemon_time": random.uniform(0.0005, 0.002),
        "application_time": app_time,
        "application_time_buckets": bucketise(count, concentration=6),
        "server_time_buckets": bucketise(count, concentration=7),
        "request_time_buckets": bucketise(count, concentration=5),
        "slot_request_count": slot_request_count,
        "slot_busy_time_us": slot_busy_time_us,
        "slot_cpu_time_us": slot_cpu_time_us,
        "slot_current_elapsed_ms": slot_current_elapsed_ms,
        "slot_max_duration_ms": slot_max_duration_ms,
        # Per-request avg ~256 B in / ~1 KB out, with a small tail of
        # streaming responses that bump output_writes well above the
        # request count so the UI's "bytes/write" smell threshold is
        # exercised on demo data.
        "input_bytes_total": count * 256,
        "input_reads_total": count,
        "output_bytes_total": count * 1024,
        "output_writes_total": count + (count // 5) * 50,
        # Mirror what a real reporter emits: telemetry interval is the
        # tick we're simulating, slow_requests_threshold pretends a
        # WSGISlowRequests of 1 s so the UI's "below server threshold"
        # warning can be exercised by setting the heatmap stuck
        # threshold to 0.5 s.
        "telemetry_interval": float(interval),
        "slow_requests_threshold": 1.0,
    }

    return Sample(
        version=1,
        kind=KIND_REQUEST,
        pid=pid,
        seq=seq,
        stamp_us=int(time.time() * 1_000_000),
        fields=fields,
    )


def make_slow_sample(pid: int, seq: int, state: int, thread_id: int,
                     log_id: str, method: str, path: str,
                     start_stamp_us: int, duration_us: int) -> Sample:
    """Build one synthetic slow_request record."""
    # Synthesise plausible per-request I/O so the slow-request expand
    # panel shows non-zero counters in the simulator. POSTs get a body
    # in; the long /api/search/* path streams a big response across
    # many writes so the UI's smell tinting kicks in.
    if method == "POST":
        in_bytes = random.randint(2_000, 50_000)
        in_reads = random.randint(1, 4)
    else:
        in_bytes = 0
        in_reads = 0
    streaming = "search" in path
    out_bytes = random.randint(50_000_000, 150_000_000) if streaming \
                else random.randint(2_000, 200_000)
    out_writes = random.randint(40_000, 120_000) if streaming \
                 else random.randint(1, 10)
    # Synthesise plausible CPU time so the UI's CPU% indicator (and
    # its amber / multi-core tinting) is exercisable on demo data.
    # Streaming endpoints look I/O-bound (low CPU%); checkout looks
    # multi-core (>100% via C-extension threading); the rest land in
    # the mixed band so the colouring isn't all one shade.
    if state == 1:
        if streaming:
            cpu_total_us = int(duration_us * random.uniform(0.05, 0.20))
        elif "checkout" in path:
            cpu_total_us = int(duration_us * random.uniform(1.10, 1.40))
        elif "thumbnail" in path:
            cpu_total_us = int(duration_us * random.uniform(0.85, 0.98))
        else:
            cpu_total_us = int(duration_us * random.uniform(0.30, 0.60))
        cpu_user_us = int(cpu_total_us * random.uniform(0.85, 0.95))
        cpu_system_us = cpu_total_us - cpu_user_us
    else:
        # Active records carry zero CPU on the wire today (see C side).
        cpu_user_us = 0
        cpu_system_us = 0
    fields = {
        "slow_state": state,                    # 0=active, 1=completed
        "slow_start_stamp_us": start_stamp_us,
        "slow_duration_us": duration_us,
        "slow_thread_id": thread_id,
        "slow_log_id": log_id,
        "slow_method": method,
        "slow_scheme": "http",
        "slow_hostname": socket.gethostname(),
        "slow_script_name": "",
        "slow_path_info": path,
        "slow_input_bytes": in_bytes,
        "slow_input_reads": in_reads,
        "slow_output_bytes": out_bytes,
        "slow_output_writes": out_writes,
        "slow_cpu_user_us": cpu_user_us,
        "slow_cpu_system_us": cpu_system_us,
    }
    return Sample(
        version=1,
        kind=KIND_SLOW_REQUEST,
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
    slot_states: list[dict] = [dict() for _ in range(args.processes)]

    # Per-process in-flight slow requests so heartbeats + completions are
    # correlated. Keyed by a synthetic log_id so the ingester's (pid,
    # log_id) map stays consistent across ticks.
    in_flight: list[dict] = [dict() for _ in range(args.processes)]
    next_log = [1] * args.processes

    start = time.monotonic()
    sent = 0
    try:
        while True:
            if args.duration and time.monotonic() - start > args.duration:
                break
            for i in range(args.processes):
                phases[i] += args.interval / 15.0
                seqs[i] += 1
                sample = make_sample(pids[i], seqs[i], phases[i], args.interval,
                                     slot_state=slot_states[i])
                try:
                    sock.sendto(encode(sample), addr)
                    sent += 1
                except OSError as e:
                    print(f"sendto failed: {e}", file=sys.stderr)

                # --- Slow requests ------------------------------------
                # Start a new one ~30% of the time, capped at 5 per process.
                if len(in_flight[i]) < 5 and random.random() < 0.30:
                    log_id = f"s{pids[i]}-{next_log[i]:06d}"
                    next_log[i] += 1
                    method, path = random.choice(_SLOW_PATHS)
                    in_flight[i][log_id] = {
                        "method": method,
                        "path": path,
                        "thread_id": random.randint(1, 5),
                        "start_us": int(time.time() * 1_000_000),
                    }

                now_us = int(time.time() * 1_000_000)
                # Heartbeat every active.
                for log_id, rec in list(in_flight[i].items()):
                    seqs[i] += 1
                    sample = make_slow_sample(
                        pids[i], seqs[i], state=0,
                        thread_id=rec["thread_id"], log_id=log_id,
                        method=rec["method"], path=rec["path"],
                        start_stamp_us=rec["start_us"],
                        duration_us=max(0, now_us - rec["start_us"]),
                    )
                    try:
                        sock.sendto(encode(sample), addr)
                        sent += 1
                    except OSError as e:
                        print(f"sendto failed: {e}", file=sys.stderr)

                # Complete one ~25% of the time (once it's been in-flight
                # long enough to feel plausible).
                if in_flight[i] and random.random() < 0.25:
                    log_id = random.choice(list(in_flight[i]))
                    rec = in_flight[i].pop(log_id)
                    duration = max(0, now_us - rec["start_us"])
                    if duration >= 500_000:   # only "complete" if >= 0.5s
                        seqs[i] += 1
                        sample = make_slow_sample(
                            pids[i], seqs[i], state=1,
                            thread_id=rec["thread_id"], log_id=log_id,
                            method=rec["method"], path=rec["path"],
                            start_stamp_us=rec["start_us"],
                            duration_us=duration,
                        )
                        try:
                            sock.sendto(encode(sample), addr)
                            sent += 1
                        except OSError as e:
                            print(f"sendto failed: {e}", file=sys.stderr)
                    else:
                        # Not long enough yet; put it back.
                        in_flight[i][log_id] = rec

            time.sleep(args.interval)
    except KeyboardInterrupt:
        pass
    finally:
        sock.close()

    print(f"sent {sent} samples")
    return 0


if __name__ == "__main__":
    sys.exit(main())
