#!/usr/bin/env python3
# Helper for scripts/run-benchmark.sh.
#
# Hits tests/benchmark.wsgi's /metrics/reset and /metrics/report
# endpoints enough times to reach every daemon / MPM child process,
# then prints an aggregated per-process summary.

import json
import sys
import urllib.request
from concurrent.futures import ThreadPoolExecutor

TIMEOUT = 5
MAX_ROUNDS = 10


def hit(url):
    with urllib.request.urlopen(url, timeout=TIMEOUT) as resp:
        return resp.read()


def burst(url, parallelism):
    """Fire `parallelism` concurrent requests; yield response bodies."""
    with ThreadPoolExecutor(max_workers=parallelism) as ex:
        futures = [ex.submit(hit, url) for _ in range(parallelism)]
        for fut in futures:
            try:
                yield fut.result()
            except Exception as e:
                print(f"metrics: request failed: {e}", file=sys.stderr)


def collect_reset(base_url, expected):
    # Concurrent bursts force Apache to dispatch to multiple daemons at
    # once rather than serialising onto whichever is least busy.
    seen = set()
    url = base_url + "/metrics/reset"
    parallelism = max(expected * 3, 8)
    for _ in range(MAX_ROUNDS):
        for body in burst(url, parallelism):
            try:
                seen.add(int(body.decode("ascii").strip()))
            except ValueError:
                pass
        if len(seen) >= expected:
            break
    return seen


def collect_report(base_url, expected):
    # The WSGI endpoint caches its reading on first call, so repeat
    # hits on the same PID are idempotent and return identical data.
    seen = {}
    url = base_url + "/metrics/report"
    parallelism = max(expected * 3, 8)
    for _ in range(MAX_ROUNDS):
        for body in burst(url, parallelism):
            try:
                data = json.loads(body)
            except Exception:
                continue
            pid = int(data.get("pid", 0))
            if not pid or pid in seen:
                continue
            # A dict with only 'pid' means /metrics/reset never reached
            # this process, so it has no recorded data.
            if len(data) <= 1:
                continue
            seen[pid] = data
        if len(seen) >= expected:
            break
    return seen


def fmt_buckets(buckets, start=0.005):
    """Render a mod_wsgi time histogram (log2 from 5ms) as compact text."""
    if not buckets:
        return "(empty)"
    parts = []
    threshold = start
    for i, c in enumerate(buckets[:15]):
        if c:
            parts.append(f"<={threshold*1000:g}ms={c}")
        threshold *= 2
    if len(buckets) > 15 and buckets[15]:
        parts.append(f">{threshold/2*1000:g}ms={buckets[15]}")
    return " ".join(parts) if parts else "(empty)"


def summarise(seen):
    pids = sorted(seen)
    n = len(pids)
    if n == 0:
        print("No metrics collected.", file=sys.stderr)
        return

    print("")
    print("=" * 72)
    print(f"mod_wsgi.request_metrics() — {n} process(es)")
    print("=" * 72)

    agg_req = 0
    agg_tp = 0.0
    agg_cpu_user = 0.0
    agg_cpu_system = 0.0
    agg_cpu = 0.0
    agg_cap = 0.0
    agg_app = 0.0
    agg_q = 0.0
    agg_d = 0.0
    agg_srv = 0.0

    for pid in pids:
        d = seen[pid]
        period = d.get("sample_period", 0.0)
        print(f"\n  pid {pid}  (window {period:.2f}s)")
        print(f"    request_count           : {d.get('request_count', 0)}")
        print(f"    request_throughput      : {d.get('request_throughput', 0.0):8.1f} rps")
        print(f"    capacity_utilization    : {d.get('capacity_utilization', 0.0):8.3f}")
        print(f"    cpu_user_utilization    : {d.get('cpu_user_utilization', 0.0):8.3f} cores")
        print(f"    cpu_system_utilization  : {d.get('cpu_system_utilization', 0.0):8.3f} cores")
        print(f"    cpu_utilization         : {d.get('cpu_utilization', 0.0):8.3f} cores")
        print(f"    memory_rss              : {d.get('memory_rss', 0) / 1024 / 1024:8.1f} MB")
        print(f"    server_time avg         : {d.get('server_time', 0.0) * 1000:8.3f} ms")
        qt = d.get("queue_time")
        dt = d.get("daemon_time")
        if qt is not None:
            print(f"    queue_time avg          : {qt * 1000:8.3f} ms")
        if dt is not None:
            print(f"    daemon_time avg         : {dt * 1000:8.3f} ms")
        print(f"    application_time avg    : {d.get('application_time', 0.0) * 1000:8.3f} ms")

        rtb = d.get("request_threads_buckets", [])
        print(f"    per-thread req counts   : {rtb}")
        print(f"    application_buckets     : {fmt_buckets(d.get('application_time_buckets', []))}")
        if qt is not None:
            print(f"    queue_time_buckets      : {fmt_buckets(d.get('queue_time_buckets', []))}")

        agg_req += d.get("request_count", 0)
        agg_tp += d.get("request_throughput", 0.0)
        agg_cpu_user += d.get("cpu_user_utilization", 0.0)
        agg_cpu_system += d.get("cpu_system_utilization", 0.0)
        agg_cpu += d.get("cpu_utilization", 0.0)
        agg_cap += d.get("capacity_utilization", 0.0)
        agg_app += d.get("application_time", 0.0)
        agg_q += qt or 0.0
        agg_d += dt or 0.0
        agg_srv += d.get("server_time", 0.0)

    print("")
    print(f"  aggregate")
    print(f"    sampled requests        : {agg_req}")
    print(f"    sum throughput          : {agg_tp:8.1f} rps")
    print(f"    sum cpu_user            : {agg_cpu_user:8.2f} cores")
    print(f"    sum cpu_system          : {agg_cpu_system:8.2f} cores")
    print(f"    sum cpu_utilization     : {agg_cpu:8.2f} cores")
    print(f"    mean capacity_util      : {agg_cap / n:8.3f}")
    print(f"    mean application_time   : {agg_app / n * 1000:8.3f} ms")
    if agg_q:
        print(f"    mean queue_time         : {agg_q / n * 1000:8.3f} ms")
    if agg_d:
        print(f"    mean daemon_time        : {agg_d / n * 1000:8.3f} ms")
    print(f"    mean server_time        : {agg_srv / n * 1000:8.3f} ms")
    print("")


def main():
    if len(sys.argv) < 4:
        print(f"usage: {sys.argv[0]} <reset|report> <base_url> <expected_pid_count>",
              file=sys.stderr)
        sys.exit(1)
    mode = sys.argv[1]
    base_url = sys.argv[2].rstrip("/")
    expected = int(sys.argv[3])

    if mode == "reset":
        seen = collect_reset(base_url, expected)
        msg = f"metrics: reset seeded {len(seen)}/{expected} process(es): {sorted(seen)}"
        if len(seen) < expected:
            msg += "  WARNING: some processes unreached"
        print(msg, file=sys.stderr)
    elif mode == "report":
        seen = collect_report(base_url, expected)
        if len(seen) < expected:
            print(f"metrics: WARNING — only {len(seen)}/{expected} process(es) reported",
                  file=sys.stderr)
        summarise(seen)
    else:
        print(f"unknown mode: {mode}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
