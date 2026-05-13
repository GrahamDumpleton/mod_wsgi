"""Terminal monitor for mod_wsgi telemetry.

Connects to a running ``mod_wsgi-telemetry serve`` ingester's WebSocket and
renders the live state as a top-style terminal UI. Multiple views switchable
by keystroke; the persistent header stays visible across views.

Usage:
    mod_wsgi-telemetry top                         # connect to localhost
    mod_wsgi-telemetry top --url ws://host:8877/ws
    mod_wsgi-telemetry top --view slow             # start on slow-requests view
    mod_wsgi-telemetry top --once                  # render one frame and exit
"""

from __future__ import annotations

import argparse
import asyncio
import curses
import json
import logging
import math
import os
import signal
import sys
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any

import aiohttp


PHASES = ["server", "queue", "daemon", "application", "request"]

# HDR histogram layout. Mirrors the daemon-side encoder: 16 octaves, each
# split into 4 sub-buckets, plus 1 overflow bucket = 65 entries. Bucket 0
# covers [1ms, 1.25ms), bucket 1 [1.25ms, 1.5ms), and so on; bucket 64 is
# >65.5s.
HDR_OCTAVES = 16
HDR_SUBS = 4
HDR_TOTAL = HDR_OCTAVES * HDR_SUBS + 1
HDR_BASE_SECONDS = 0.001  # bucket 0 lower bound: 1 ms expressed as seconds

DEFAULT_URL = "ws://127.0.0.1:8877/ws"
SAMPLE_RETENTION = 600          # max samples per pid we keep client-side
REFRESH_RATES = [0.5, 1.0, 2.0, 5.0]
WINDOW_CHOICES = [10, 60, 600]  # rolling window in seconds for overview/latency

VIEWS = ["overview", "processes", "workers", "latency", "slow"]
VIEW_KEYS = {
    ord("o"): "overview", ord("1"): "overview",
    ord("p"): "processes", ord("2"): "processes",
    ord("w"): "workers", ord("3"): "workers",
    ord("l"): "latency", ord("4"): "latency",
    ord("s"): "slow", ord("5"): "slow",
}

SPARK_BLOCKS = " ▁▂▃▄▅▆▇█"
BAR_FULL = "█"
BAR_EMPTY = "░"

# Color pair IDs.
CP_HEADER = 1
CP_OK = 2
CP_WARN = 3
CP_CRIT = 4
CP_DIM = 5
CP_BAR = 6
CP_TAB = 7
CP_TAB_ACTIVE = 8


# ---------------------------------------------------------------------------
# State mirror
# ---------------------------------------------------------------------------


@dataclass
class ProcState:
    """Client-side mirror of the ingester's per-pid rolling window."""
    pid: int
    hostname: str = ""
    process_group: str = ""
    mod_wsgi_version: str = ""
    python_version: str = ""
    apache_version: str = ""
    mpm_name: str = ""
    sample_period: float = 1.0
    samples: deque = field(default_factory=lambda: deque(maxlen=SAMPLE_RETENTION))
    last_seen: float = 0.0


@dataclass
class SlowEntry:
    pid: int
    thread_id: int
    log_id: str
    method: str
    scheme: str
    hostname: str
    script_name: str
    path_info: str
    start_stamp: float
    duration: float
    state: int
    input_bytes: int
    input_reads: int
    output_bytes: int
    output_writes: int
    cpu_user_time: float
    cpu_system_time: float
    status: int = 0
    last_seen: float = 0.0

    @classmethod
    def from_dict(cls, d: dict) -> "SlowEntry":
        return cls(
            pid=int(d["pid"]),
            thread_id=int(d["thread_id"]),
            log_id=d["log_id"],
            method=d["method"],
            scheme=d["scheme"],
            hostname=d["hostname"],
            script_name=d["script_name"],
            path_info=d["path_info"],
            start_stamp=float(d["start_stamp"]),
            duration=float(d["duration"]),
            state=int(d["state"]),
            input_bytes=int(d.get("input_bytes", 0)),
            input_reads=int(d.get("input_reads", 0)),
            output_bytes=int(d.get("output_bytes", 0)),
            output_writes=int(d.get("output_writes", 0)),
            cpu_user_time=float(d.get("cpu_user_time", 0.0)),
            cpu_system_time=float(d.get("cpu_system_time", 0.0)),
            status=int(d.get("status", 0)),
            last_seen=time.monotonic(),
        )

    def url(self) -> str:
        path = (self.script_name or "") + (self.path_info or "")
        return path or "/"


class State:
    """Snapshot + live-sample mirror of the ingester."""

    def __init__(self) -> None:
        self.processes: dict[int, ProcState] = {}
        self.slow: dict[tuple, SlowEntry] = {}
        self.connected: bool = False
        self.url: str = ""
        self.last_message: float = 0.0
        self.last_error: str = ""
        self.total_received: int = 0
        self.decode_errors: int = 0

    def apply(self, msg: dict) -> None:
        t = msg.get("type")
        if t == "snapshot":
            self._apply_snapshot(msg)
        elif t == "sample":
            self._apply_sample(msg)
        elif t == "slow_request":
            self._apply_slow(msg)
        elif t == "slow_clear":
            self._apply_slow_clear(msg)
        self.last_message = time.monotonic()

    def _apply_snapshot(self, msg: dict) -> None:
        self.total_received = int(msg.get("total_received", 0))
        self.decode_errors = int(msg.get("decode_errors", 0))
        self.processes.clear()
        for p in msg.get("processes", []):
            pid = int(p["pid"])
            ps = ProcState(
                pid=pid,
                hostname=p.get("hostname", ""),
                process_group=p.get("process_group", ""),
                mod_wsgi_version=p.get("mod_wsgi_version", ""),
                python_version=p.get("python_version", ""),
                apache_version=p.get("apache_version", ""),
                mpm_name=p.get("mpm_name", ""),
                last_seen=time.monotonic(),
            )
            for s in p.get("samples", []):
                ps.samples.append(s)
                fields = s.get("fields", {})
                sp = fields.get("sample_period")
                if isinstance(sp, (int, float)) and sp > 0:
                    ps.sample_period = float(sp)
            self.processes[pid] = ps
        self.slow.clear()
        for r in msg.get("slow_requests", []):
            entry = SlowEntry.from_dict(r["entry"])
            key = tuple(r["key"])
            self.slow[key] = entry

    def _apply_sample(self, msg: dict) -> None:
        self.total_received += 1
        pid = int(msg["pid"])
        ps = self.processes.get(pid)
        if ps is None:
            ps = ProcState(pid=pid)
            self.processes[pid] = ps
        ps.samples.append(msg)
        ps.last_seen = time.monotonic()
        fields = msg.get("fields", {})

        def _latch(name: str, attr: str) -> None:
            v = fields.get(name)
            if isinstance(v, str) and v:
                setattr(ps, attr, v)

        _latch("hostname", "hostname")
        _latch("process_group", "process_group")
        _latch("mod_wsgi_version", "mod_wsgi_version")
        _latch("python_version", "python_version")
        _latch("apache_version", "apache_version")
        _latch("mpm_name", "mpm_name")

        sp = fields.get("sample_period")
        if isinstance(sp, (int, float)) and sp > 0:
            ps.sample_period = float(sp)

    def _apply_slow(self, msg: dict) -> None:
        key = tuple(msg["key"])
        self.slow[key] = SlowEntry.from_dict(msg["entry"])

    def _apply_slow_clear(self, msg: dict) -> None:
        kept = {tuple(k["key"]): SlowEntry.from_dict(k["entry"])
                for k in msg.get("kept", [])}
        self.slow = kept


# ---------------------------------------------------------------------------
# Aggregation helpers
# ---------------------------------------------------------------------------


def _samples_in_window(ps: ProcState, seconds: float) -> list[dict]:
    """Newest-first samples within the given wall-clock window."""
    if not ps.samples:
        return []
    newest = ps.samples[-1].get("stamp", 0.0)
    cutoff = newest - seconds
    out = []
    for s in reversed(ps.samples):
        if s.get("stamp", 0.0) < cutoff:
            break
        out.append(s)
    return out


def _last_field(ps: ProcState, name: str, default=0):
    if not ps.samples:
        return default
    return ps.samples[-1].get("fields", {}).get(name, default)


def _hdr_bucket_bounds(idx: int) -> tuple[float, float]:
    """Lower/upper bound (seconds) of bucket `idx`."""
    if idx >= HDR_OCTAVES * HDR_SUBS:
        return (HDR_BASE_SECONDS * (1 << HDR_OCTAVES), float("inf"))
    octave = idx // HDR_SUBS
    sub = idx % HDR_SUBS
    octave_lo = HDR_BASE_SECONDS * (1 << octave)
    sub_width = octave_lo / HDR_SUBS
    return (octave_lo + sub * sub_width, octave_lo + (sub + 1) * sub_width)


def _hdr_percentile(buckets: list[int], pct: float) -> float | None:
    """Linear interpolation inside the bucket containing the percentile."""
    total = sum(buckets)
    if total <= 0:
        return None
    target = pct * total / 100.0
    cumulative = 0
    for i, c in enumerate(buckets):
        if c <= 0:
            continue
        if cumulative + c >= target:
            lo, hi = _hdr_bucket_bounds(i)
            if math.isinf(hi):
                return lo
            frac = (target - cumulative) / c
            return lo + frac * (hi - lo)
        cumulative += c
    return None


def _aggregate_buckets(
    state: State, phase: str, seconds: float, group_filter: str | None
) -> list[int]:
    """Sum HDR buckets for `phase` across processes within the window."""
    name = f"{phase}_time_buckets"
    out = [0] * HDR_TOTAL
    for ps in state.processes.values():
        if group_filter and ps.process_group != group_filter:
            continue
        for s in _samples_in_window(ps, seconds):
            buckets = s.get("fields", {}).get(name)
            if isinstance(buckets, list) and len(buckets) == HDR_TOTAL:
                for i, c in enumerate(buckets):
                    out[i] += c
    return out


def _phase_min_max(
    state: State, phase: str, seconds: float, group_filter: str | None
) -> tuple[float | None, float | None]:
    """Min-of-mins, max-of-maxes (seconds) for `phase` in window."""
    min_name = f"{phase}_time_min"
    max_name = f"{phase}_time_max"
    lo: float | None = None
    hi: float | None = None
    for ps in state.processes.values():
        if group_filter and ps.process_group != group_filter:
            continue
        for s in _samples_in_window(ps, seconds):
            f = s.get("fields", {})
            v = f.get(min_name)
            if isinstance(v, (int, float)) and v > 0:
                lo = v if lo is None else min(lo, v)
            v = f.get(max_name)
            if isinstance(v, (int, float)) and v > 0:
                hi = v if hi is None else max(hi, v)
    return lo, hi


def _process_groups(state: State) -> list[str]:
    seen = sorted({ps.process_group for ps in state.processes.values()
                   if ps.process_group})
    return seen


# ---------------------------------------------------------------------------
# Formatters
# ---------------------------------------------------------------------------


def fmt_bytes(n: float) -> str:
    if n < 1024:
        return f"{int(n)}B"
    for unit in ("KB", "MB", "GB", "TB"):
        n /= 1024
        if n < 1024:
            return f"{n:.1f}{unit}"
    return f"{n:.1f}PB"


def fmt_seconds(s: float | int | None) -> str:
    """Render a duration in seconds as a human-readable string."""
    if s is None:
        return "-"
    if s < 0.001:
        return f"{s*1_000_000:.0f}µs"
    if s < 1.0:
        return f"{s*1000:.1f}ms"
    return f"{s:.2f}s"


def sparkline(values: list[float], width: int) -> str:
    if width <= 0 or not values:
        return ""
    if len(values) > width:
        # downsample by averaging windows
        step = len(values) / width
        out = []
        for i in range(width):
            lo = int(i * step)
            hi = max(lo + 1, int((i + 1) * step))
            out.append(sum(values[lo:hi]) / max(1, hi - lo))
        values = out
    elif len(values) < width:
        values = [0.0] * (width - len(values)) + values
    vmax = max(values) if values else 0.0
    if vmax <= 0:
        return SPARK_BLOCKS[0] * width
    levels = len(SPARK_BLOCKS) - 1
    return "".join(
        SPARK_BLOCKS[min(levels, max(0, int(v / vmax * levels)))]
        for v in values
    )


# ---------------------------------------------------------------------------
# Curses-safe drawing
# ---------------------------------------------------------------------------


def safe_addstr(win, y: int, x: int, text: str, attr: int = 0) -> None:
    """addstr that won't raise if it bumps the bottom-right cell."""
    try:
        h, w = win.getmaxyx()
        if y < 0 or y >= h or x >= w:
            return
        if x < 0:
            text = text[-x:]
            x = 0
        avail = w - x
        if avail <= 0:
            return
        if len(text) > avail:
            text = text[:avail]
        win.addstr(y, x, text, attr)
    except curses.error:
        pass


# ---------------------------------------------------------------------------
# View renderers
# ---------------------------------------------------------------------------


@dataclass
class UIState:
    view: str = "overview"
    paused: bool = False
    refresh_idx: int = 1                # 1.0 s
    window_idx: int = 1                 # 60 s
    phase_idx: int = 4                  # request
    process_sort: str = "rps"           # rps|cpu|rss|p95|slow|pid
    slow_sort: str = "elapsed"          # elapsed|pid|method|url
    slow_state_filter: int = -1         # -1=any, 0=active, 1=completed
    slow_search: str = ""
    group_filter: str | None = None
    show_help: bool = False

    @property
    def refresh(self) -> float:
        return REFRESH_RATES[self.refresh_idx]

    @property
    def window(self) -> int:
        return WINDOW_CHOICES[self.window_idx]

    @property
    def phase(self) -> str:
        return PHASES[self.phase_idx]


def _aggregate_header(state: State, ui: UIState) -> dict:
    """Compute the always-visible header values once per render."""
    rps_now = 0.0
    in_bytes_per_s = 0.0
    out_bytes_per_s = 0.0
    cpu_user = 0.0
    cpu_sys = 0.0
    rss_total = 0
    rss_max = 0
    busy = 0
    threads_total = 0
    queue_mean = 0.0
    queue_count = 0

    rps_window: dict[int, list[tuple[int, int]]] = {}
    status_1xx = 0
    status_2xx = 0
    status_3xx = 0
    status_4xx = 0
    status_5xx = 0
    interval_requests = 0
    for ps in state.processes.values():
        if ui.group_filter and ps.process_group != ui.group_filter:
            continue
        if not ps.samples:
            continue
        last = ps.samples[-1]
        f = last.get("fields", {})
        rps_now += float(f.get("request_throughput") or 0)
        in_bytes_per_s += float(f.get("input_bytes_total") or 0) / max(1e-3, ps.sample_period)
        out_bytes_per_s += float(f.get("output_bytes_total") or 0) / max(1e-3, ps.sample_period)
        cpu_user += float(f.get("cpu_user_utilization") or 0)
        cpu_sys += float(f.get("cpu_system_utilization") or 0)
        rss = int(f.get("memory_rss") or 0)
        rss_total += rss
        rss_max = max(rss_max, int(f.get("memory_max_rss") or 0))
        active = int(f.get("request_threads_active") or 0)
        maximum = int(f.get("request_threads_maximum") or 0)
        busy += active
        threads_total += maximum
        qt = f.get("queue_time")
        if isinstance(qt, (int, float)) and qt > 0:
            queue_mean += qt
            queue_count += 1
        status_1xx += int(f.get("status_1xx_total") or 0)
        status_2xx += int(f.get("status_2xx_total") or 0)
        status_3xx += int(f.get("status_3xx_total") or 0)
        status_4xx += int(f.get("status_4xx_total") or 0)
        status_5xx += int(f.get("status_5xx_total") or 0)
        interval_requests += int(f.get("request_count") or 0)

    # 1-min and 10-min RPS averages: total request_count over window / seconds.
    rps_1m = _avg_rps(state, ui, 60)
    rps_10m = _avg_rps(state, ui, 600)

    buckets = _aggregate_buckets(state, "request", ui.window, ui.group_filter)
    p50 = _hdr_percentile(buckets, 50)
    p95 = _hdr_percentile(buckets, 95)
    p99 = _hdr_percentile(buckets, 99)
    lo, hi = _phase_min_max(state, "request", ui.window, ui.group_filter)

    now = time.time()
    active_slow = sum(1 for e in state.slow.values() if e.state == 0)
    recent_slow = sum(
        1 for e in state.slow.values()
        if (now - e.start_stamp) <= 60
    )
    total_slow = len(state.slow)

    return {
        "rps_now": rps_now,
        "rps_1m": rps_1m,
        "rps_10m": rps_10m,
        "in_bps": in_bytes_per_s,
        "out_bps": out_bytes_per_s,
        "cpu_user": cpu_user,
        "cpu_sys": cpu_sys,
        "rss_total": rss_total,
        "rss_max": rss_max,
        "busy": busy,
        "threads_total": threads_total,
        "queue_mean": (queue_mean / queue_count) if queue_count else None,
        "p50": p50, "p95": p95, "p99": p99,
        "min": lo, "max": hi,
        "active_slow": active_slow,
        "recent_slow": recent_slow,
        "total_slow": total_slow,
        "status_1xx": status_1xx,
        "status_2xx": status_2xx,
        "status_3xx": status_3xx,
        "status_4xx": status_4xx,
        "status_5xx": status_5xx,
        "interval_requests": interval_requests,
    }


def _avg_rps(state: State, ui: UIState, seconds: float) -> float:
    total = 0
    spans: list[float] = []
    for ps in state.processes.values():
        if ui.group_filter and ps.process_group != ui.group_filter:
            continue
        win = _samples_in_window(ps, seconds)
        if len(win) < 2:
            continue
        oldest = win[-1].get("stamp", 0.0)
        newest = win[0].get("stamp", 0.0)
        span = newest - oldest
        if span <= 0:
            continue
        rc = sum(int(s.get("fields", {}).get("request_count") or 0) for s in win)
        total += rc
        spans.append(span)
    if not spans:
        return 0.0
    return total / (sum(spans) / len(spans))


def render_header(win, state: State, ui: UIState, h: dict) -> int:
    """Draw the persistent header. Returns the row count consumed."""
    width = win.getmaxyx()[1]
    hostname = ""
    pgroup = ui.group_filter or ""
    sample_period = 0.0
    if state.processes:
        ps = next(iter(state.processes.values()))
        hostname = ps.hostname
        if not pgroup:
            groups = _process_groups(state)
            pgroup = ",".join(groups) if groups else "(any)"
        sample_period = ps.sample_period

    # Line 0 — title bar + connection state.
    title = f" mod_wsgi-telemetry top  {hostname or '-'} · {pgroup} "
    status = "[paused]" if ui.paused else ("[live]" if state.connected else "[disconnected]")
    extras = f" tick={sample_period:.1f}s  refresh={ui.refresh:g}s  win={_win_label(ui.window)}  {status} "
    pad = " " * max(0, width - len(title) - len(extras))
    safe_addstr(win, 0, 0, title + pad + extras, curses.color_pair(CP_HEADER) | curses.A_BOLD)

    # Line 1 — throughput. No padding on rps_now so the value starts
    # at column 13, lining up vertically with the labels on the rows
    # below (Capacity:, CPU:, Status:, Latency:, Slow:).
    safe_addstr(win, 1, 0,
        f" Throughput: {h['rps_now']:.1f} req/s now  "
        f"{h['rps_1m']:.1f}/s 1m  {h['rps_10m']:.1f}/s 10m  "
        f"in {fmt_bytes(h['in_bps'])}/s  out {fmt_bytes(h['out_bps'])}/s")

    # Line 2 — capacity bar.
    cap_total = h["threads_total"]
    cap_busy = h["busy"]
    frac = (cap_busy / cap_total) if cap_total else 0.0
    bar_w = max(10, min(30, width - 60))
    filled = int(round(frac * bar_w))
    bar = BAR_FULL * filled + BAR_EMPTY * (bar_w - filled)
    cap_attr = _cap_color(frac)
    qstr = (f"queue {fmt_seconds(h['queue_mean'])}"
            if h["queue_mean"] is not None else "queue -")
    safe_addstr(win, 2, 0, " Capacity:   ")
    safe_addstr(win, 2, 13, bar, cap_attr)
    safe_addstr(win, 2, 13 + bar_w + 1,
                f" {cap_busy:>4d}/{cap_total:<4d} threads busy "
                f"({frac*100:5.1f}%)  {qstr}")

    # Line 3 — CPU + memory.
    safe_addstr(win, 3, 0,
        f" CPU:        user {h['cpu_user']:.2f}  sys {h['cpu_sys']:.2f}  "
        f"total {h['cpu_user']+h['cpu_sys']:.2f} cores   "
        f"Memory: RSS {fmt_bytes(h['rss_total'])} (max {fmt_bytes(h['rss_max'])})")

    # Line 4 — per-class HTTP response distribution for the latest
    # interval. 2xx / 3xx / 4xx / 5xx as percentages of request_count.
    # 1xx is a PEP 3333 tripwire (a WSGI app should never return 1xx)
    # so it carries its raw count and renders amber when > 0; dim when
    # zero. 5xx renders red-bold when > 0; 4xx is dim (mostly noise).
    requests = h["interval_requests"]
    def _pct(n):
        return (n / requests * 100.0) if requests > 0 else 0.0
    safe_addstr(win, 4, 0, " Status:     ")
    x = len(" Status:     ")
    s1 = f"1xx {h['status_1xx']}"
    s1_attr = (curses.color_pair(CP_WARN) | curses.A_BOLD) if h["status_1xx"] > 0 \
              else curses.color_pair(CP_DIM)
    safe_addstr(win, 4, x, s1, s1_attr)
    x += len(s1) + 2
    s2 = f"2xx {_pct(h['status_2xx']):5.1f}%"
    safe_addstr(win, 4, x, s2)
    x += len(s2) + 2
    s3 = f"3xx {_pct(h['status_3xx']):5.1f}%"
    safe_addstr(win, 4, x, s3)
    x += len(s3) + 2
    s4 = f"4xx {_pct(h['status_4xx']):5.1f}%"
    safe_addstr(win, 4, x, s4, curses.color_pair(CP_DIM))
    x += len(s4) + 2
    s5 = f"5xx {_pct(h['status_5xx']):5.1f}%"
    s5_attr = (curses.color_pair(CP_CRIT) | curses.A_BOLD) if h["status_5xx"] > 0 \
              else curses.color_pair(CP_DIM)
    safe_addstr(win, 4, x, s5, s5_attr)

    # Line 5 — latency percentiles.
    p50 = fmt_seconds(h["p50"]); p95 = fmt_seconds(h["p95"]); p99 = fmt_seconds(h["p99"])
    mn = fmt_seconds(h["min"]); mx = fmt_seconds(h["max"])
    safe_addstr(win, 5, 0,
        f" Latency:    p50 {p50:>8}  p95 {p95:>8}  p99 {p99:>8}   "
        f"min {mn:>8}  max {mx:>8}")

    # Line 6 — slow-request counters.
    safe_addstr(win, 6, 0,
        f" Slow:       {h['active_slow']} active  /  "
        f"{h['recent_slow']} 1m  /  {h['total_slow']} total")

    # Line 7 — tab bar.
    _render_tabs(win, 7, width, ui.view)
    return 8


def _win_label(seconds: int) -> str:
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60}m"
    return f"{seconds // 3600}h"


def _cap_color(frac: float) -> int:
    if frac >= 0.9:
        return curses.color_pair(CP_CRIT) | curses.A_BOLD
    if frac >= 0.7:
        return curses.color_pair(CP_WARN)
    return curses.color_pair(CP_OK)


def _render_tabs(win, y: int, width: int, active: str) -> None:
    safe_addstr(win, y, 0, " " * width, curses.color_pair(CP_TAB))
    x = 1
    for i, name in enumerate(VIEWS, start=1):
        label = f" {i} {name} "
        attr = curses.color_pair(CP_TAB_ACTIVE) | curses.A_BOLD if name == active \
            else curses.color_pair(CP_TAB)
        safe_addstr(win, y, x, label, attr)
        x += len(label)
        if x >= width:
            break
    hint = " ?=help  q=quit "
    safe_addstr(win, y, max(x, width - len(hint)), hint, curses.color_pair(CP_TAB))


# --- Overview view -----------------------------------------------------------


def render_overview(win, state: State, ui: UIState, h: dict, y0: int) -> None:
    height, width = win.getmaxyx()
    avail = height - y0 - 1
    if avail <= 0:
        return
    # Build a per-second time series for the window using the most-active pid
    # as the time reference. Aggregate across pids on each second.
    seconds = ui.window
    rps_series, cap_series, cpu_series, rss_series = _build_series(state, ui, seconds)

    spark_w = max(20, width - 18)
    rows = [
        ("Throughput  ", rps_series, lambda v: f"{v:.1f}/s now"),
        ("Capacity %  ", cap_series, lambda v: f"{v*100:.0f}% now"),
        ("CPU cores   ", cpu_series, lambda v: f"{v:.2f}/core"),
        ("RSS MB      ", rss_series, lambda v: f"{v/1_048_576:.0f} MB"),
    ]
    y = y0 + 1
    safe_addstr(win, y0, 1, f"Overview — last {_win_label(seconds)} (use < > to change window)",
                curses.A_BOLD)
    for label, series, fmt in rows:
        if y >= height - 1:
            return
        safe_addstr(win, y, 1, label)
        line = sparkline(series, spark_w)
        safe_addstr(win, y, 13, line)
        if series:
            safe_addstr(win, y, 14 + spark_w, fmt(series[-1]))
        y += 1

    y += 1
    if y >= height - 1:
        return
    safe_addstr(win, y, 1, "Phase mean times (current tick):", curses.A_BOLD)
    y += 1
    if y >= height - 1:
        return
    parts = []
    for phase in PHASES:
        v = _aggregate_phase_mean(state, phase, ui.group_filter)
        parts.append(f"{phase}={fmt_seconds(v) if v is not None else '-':>8}")
    safe_addstr(win, y, 1, "  ".join(parts))


def _build_series(state: State, ui: UIState, seconds: int):
    """Per-second aggregated series across pids for the last `seconds`."""
    # Bucket samples by their second-stamp.
    buckets: dict[int, dict[str, float]] = {}
    for ps in state.processes.values():
        if ui.group_filter and ps.process_group != ui.group_filter:
            continue
        for s in _samples_in_window(ps, seconds):
            t = int(s.get("stamp", 0.0))
            f = s.get("fields", {})
            b = buckets.setdefault(t, {"rps": 0.0, "cap_b": 0, "cap_t": 0,
                                       "cpu": 0.0, "rss": 0})
            b["rps"] += float(f.get("request_throughput") or 0)
            b["cap_b"] += int(f.get("request_threads_active") or 0)
            b["cap_t"] += int(f.get("request_threads_maximum") or 0)
            b["cpu"] += float(f.get("cpu_utilization") or 0)
            b["rss"] += int(f.get("memory_rss") or 0)
    keys = sorted(buckets)
    rps = [buckets[k]["rps"] for k in keys]
    cap = [(buckets[k]["cap_b"] / buckets[k]["cap_t"]) if buckets[k]["cap_t"] else 0.0
           for k in keys]
    cpu = [buckets[k]["cpu"] for k in keys]
    rss = [buckets[k]["rss"] for k in keys]
    return rps, cap, cpu, rss


def _aggregate_phase_mean(state: State, phase: str, group_filter: str | None):
    """Sample-weighted mean of last-tick `<phase>_time` across processes."""
    name = f"{phase}_time"
    total = 0.0
    n = 0
    for ps in state.processes.values():
        if group_filter and ps.process_group != group_filter:
            continue
        if not ps.samples:
            continue
        v = ps.samples[-1].get("fields", {}).get(name)
        if isinstance(v, (int, float)) and v > 0:
            total += v
            n += 1
    return (total / n) if n else None


# --- Processes view ----------------------------------------------------------


def render_processes(win, state: State, ui: UIState, y0: int) -> None:
    height, width = win.getmaxyx()
    rows = []
    for ps in state.processes.values():
        if ui.group_filter and ps.process_group != ui.group_filter:
            continue
        if not ps.samples:
            continue
        f = ps.samples[-1].get("fields", {})
        buckets = []
        for s in _samples_in_window(ps, 60):
            b = s.get("fields", {}).get("request_time_buckets")
            if isinstance(b, list) and len(b) == HDR_TOTAL:
                if not buckets:
                    buckets = list(b)
                else:
                    for i, c in enumerate(b):
                        buckets[i] += c
        p95 = _hdr_percentile(buckets, 95) if buckets else None
        slow_count = sum(1 for k, e in state.slow.items() if e.pid == ps.pid)
        rows.append({
            "pid": ps.pid,
            "group": ps.process_group or "-",
            "active": int(f.get("request_threads_active") or 0),
            "max": int(f.get("request_threads_maximum") or 0),
            "rps": float(f.get("request_throughput") or 0),
            "cpu": float(f.get("cpu_utilization") or 0),
            "rss": int(f.get("memory_rss") or 0),
            "p95": p95,
            "slow": slow_count,
        })

    sort_key = ui.process_sort
    keyfn = {
        "rps": lambda r: -r["rps"],
        "cpu": lambda r: -r["cpu"],
        "rss": lambda r: -r["rss"],
        "p95": lambda r: -(r["p95"] or 0),
        "slow": lambda r: -r["slow"],
        "pid": lambda r: r["pid"],
    }.get(sort_key, lambda r: -r["rps"])
    rows.sort(key=keyfn)

    safe_addstr(win, y0, 1,
        f"Processes — sort: {sort_key} (use < > to change)   "
        f"{len(rows)} pids", curses.A_BOLD)
    header = f"  {'PID':>7}  {'GROUP':<16}  {'THREADS':>9}  {'RPS':>7}  " \
             f"{'CPU':>6}  {'RSS':>9}  {'P95':>9}  {'SLOW':>5}"
    safe_addstr(win, y0 + 1, 0, header, curses.A_REVERSE)
    y = y0 + 2
    for r in rows:
        if y >= height - 1:
            break
        line = (f"  {r['pid']:>7}  {r['group'][:16]:<16}  "
                f"{r['active']:>4}/{r['max']:<4}  "
                f"{r['rps']:>7.1f}  "
                f"{r['cpu']:>6.2f}  "
                f"{fmt_bytes(r['rss']):>9}  "
                f"{fmt_seconds(r['p95']):>9}  "
                f"{r['slow']:>5}")
        attr = 0
        if r["max"] and r["active"] / r["max"] >= 0.9:
            attr = curses.color_pair(CP_CRIT)
        elif r["max"] and r["active"] / r["max"] >= 0.7:
            attr = curses.color_pair(CP_WARN)
        safe_addstr(win, y, 0, line, attr)
        y += 1


# --- Workers / slots view ----------------------------------------------------


def render_workers(win, state: State, ui: UIState, y0: int) -> None:
    height, width = win.getmaxyx()
    safe_addstr(win, y0, 1,
        "Workers — slot grid: . idle  * <1s  # 1-5s  ! >=slow-threshold",
        curses.A_BOLD)
    y = y0 + 1
    pids = sorted(state.processes.keys())
    for pid in pids:
        if y >= height - 1:
            break
        ps = state.processes[pid]
        if ui.group_filter and ps.process_group != ui.group_filter:
            continue
        if not ps.samples:
            continue
        last = ps.samples[-1].get("fields", {})
        elapsed = last.get("request_threads_current_elapsed")
        slow_thresh = last.get("slow_requests_threshold")
        slow_thresh = (slow_thresh
                       if isinstance(slow_thresh, (int, float)) and slow_thresh > 0
                       else None)
        if not isinstance(elapsed, list):
            continue
        cells = []
        longest_idx = -1
        longest = 0.0
        for i, e in enumerate(elapsed):
            if e <= 0:
                cells.append(".")
            elif slow_thresh is not None and e >= slow_thresh:
                cells.append("!")
            elif e >= 5.0:
                cells.append("#")
            elif e >= 1.0:
                cells.append("#")
            else:
                cells.append("*")
            if e > longest:
                longest = e
                longest_idx = i

        label = f"  pid {pid:<6} {ps.process_group[:14]:<14}"
        safe_addstr(win, y, 0, label)
        # Truncate slot row to terminal width.
        avail = width - len(label) - 2
        row = "".join(cells[:avail]) if avail > 0 else ""
        # Color cells: red for !, yellow for #, default for *.
        cx = len(label) + 1
        for ch in row:
            if cx >= width:
                break
            attr = 0
            if ch == "!":
                attr = curses.color_pair(CP_CRIT) | curses.A_BOLD
            elif ch == "#":
                attr = curses.color_pair(CP_WARN)
            elif ch == "*":
                attr = curses.color_pair(CP_OK)
            else:
                attr = curses.color_pair(CP_DIM)
            safe_addstr(win, y, cx, ch, attr)
            cx += 1
        y += 1
        if y >= height - 1:
            break
        if longest_idx >= 0 and longest > 0:
            note = (f"           longest slot: #{longest_idx} "
                    f"running {fmt_seconds(longest)}")
            # Look for an active slow request matching this pid.
            active = [e for e in state.slow.values()
                      if e.pid == pid and e.state == 0]
            active.sort(key=lambda e: -e.duration)
            if active:
                e = active[0]
                note += f"   {e.method} {e.url()[:60]}"
            safe_addstr(win, y, 0, note, curses.color_pair(CP_DIM))
            y += 1


# --- Latency view ------------------------------------------------------------


def render_latency(win, state: State, ui: UIState, y0: int) -> None:
    height, width = win.getmaxyx()
    phase = ui.phase
    seconds = ui.window
    buckets = _aggregate_buckets(state, phase, seconds, ui.group_filter)
    total = sum(buckets)
    p50 = _hdr_percentile(buckets, 50)
    p95 = _hdr_percentile(buckets, 95)
    p99 = _hdr_percentile(buckets, 99)
    lo, hi = _phase_min_max(state, phase, seconds, ui.group_filter)

    safe_addstr(win, y0, 1,
        f"Latency — phase: {phase}  window: {_win_label(seconds)}  "
        f"samples: {total}    "
        f"([ ] phase, < > window)", curses.A_BOLD)
    safe_addstr(win, y0 + 1, 1,
        f"  p50 {fmt_seconds(p50):>8}  p95 {fmt_seconds(p95):>8}  "
        f"p99 {fmt_seconds(p99):>8}  "
        f"min {fmt_seconds(lo):>8}  max {fmt_seconds(hi):>8}")

    # Histogram. 65 buckets: render one column per bucket where it fits;
    # otherwise pair them up so the chart still spans the whole window.
    chart_top = y0 + 3
    chart_bottom = height - 2
    chart_h = max(4, chart_bottom - chart_top - 1)
    chart_left = 4
    chart_w = width - chart_left - 1
    if chart_w <= 0 or chart_h <= 0:
        return

    cols_per_bucket = max(1, chart_w // HDR_TOTAL)
    n_cols = HDR_TOTAL * cols_per_bucket
    if n_cols > chart_w:
        # Fallback: collapse buckets into chart_w cells by binning.
        per_col = math.ceil(HDR_TOTAL / chart_w)
        binned = []
        for i in range(0, HDR_TOTAL, per_col):
            binned.append(sum(buckets[i:i + per_col]))
        display = binned
        cols_per_bucket = 1
    else:
        display = []
        for c in buckets:
            display.extend([c] * cols_per_bucket)

    vmax = max(display) if display else 0
    if vmax <= 0:
        safe_addstr(win, chart_top, chart_left, "(no samples in window)",
                    curses.color_pair(CP_DIM))
        return

    levels = chart_h * 8
    # 8 sub-pixels per row using upper partial blocks.
    PARTIAL = " ▁▂▃▄▅▆▇█"
    # Render columns top-to-bottom.
    for col, count in enumerate(display):
        x = chart_left + col
        if x >= width - 1:
            break
        h_units = int(round(count / vmax * levels))
        full_rows = h_units // 8
        rem = h_units % 8
        # Bottom row anchored at chart_bottom.
        for r in range(full_rows):
            y = chart_bottom - r
            if y < chart_top:
                break
            safe_addstr(win, y, x, BAR_FULL, curses.color_pair(CP_BAR))
        if rem and full_rows < chart_h:
            y = chart_bottom - full_rows
            if y >= chart_top:
                safe_addstr(win, y, x, PARTIAL[rem], curses.color_pair(CP_BAR))

    # Octave labels along the bottom.
    label_y = chart_bottom + 1
    if label_y < height:
        # Print a label every 4 buckets (= every octave start).
        for octave in range(0, HDR_OCTAVES, 2):
            lo = HDR_BASE_SECONDS * (1 << octave)
            x = chart_left + octave * HDR_SUBS * cols_per_bucket
            if x >= width:
                break
            safe_addstr(win, label_y, x, _short_seconds(lo),
                        curses.color_pair(CP_DIM))


def _short_seconds(s: float) -> str:
    """Compact axis-tick label for a bucket boundary."""
    if s < 1.0:
        return f"{s*1000:.0f}ms"
    return f"{s:.0f}s"


# --- Slow requests view ------------------------------------------------------


def render_slow(win, state: State, ui: UIState, y0: int) -> None:
    height, width = win.getmaxyx()
    rows = []
    now = time.time()
    for key, e in state.slow.items():
        if ui.slow_state_filter != -1 and e.state != ui.slow_state_filter:
            continue
        if ui.group_filter:
            ps = state.processes.get(e.pid)
            if not ps or ps.process_group != ui.group_filter:
                continue
        if ui.slow_search and ui.slow_search.lower() not in e.url().lower():
            continue
        if e.state == 0:
            elapsed = max(e.duration, now - e.start_stamp)
        else:
            elapsed = e.duration
        rows.append((elapsed, key, e))

    sort_key = ui.slow_sort
    if sort_key == "elapsed":
        rows.sort(key=lambda r: -r[0])
    elif sort_key == "pid":
        rows.sort(key=lambda r: (r[2].pid, -r[0]))
    elif sort_key == "method":
        rows.sort(key=lambda r: (r[2].method, -r[0]))
    elif sort_key == "url":
        rows.sort(key=lambda r: (r[2].url(), -r[0]))

    state_filter = {-1: "any", 0: "active", 1: "completed"}[ui.slow_state_filter]
    title = (f"Slow requests — sort: {sort_key}  state: {state_filter}  "
             f"({len(rows)} shown / {len(state.slow)} total)   "
             f"(< > sort, f filter, / search)")
    safe_addstr(win, y0, 1, title, curses.A_BOLD)
    if ui.slow_search:
        safe_addstr(win, y0, len(title) + 2, f"search: {ui.slow_search!r}",
                    curses.color_pair(CP_WARN))

    header = f"  {'STATE':<6}  {'ELAPSED':>9}  {'PID':>7}  " \
             f"{'METHOD':<7}  {'STATUS':>6}  {'LOG ID':<24}  URL"
    safe_addstr(win, y0 + 1, 0, header, curses.A_REVERSE)
    y = y0 + 2
    for elapsed, key, e in rows:
        if y >= height - 1:
            break
        st = "active" if e.state == 0 else "done"
        attr = curses.color_pair(CP_CRIT) | curses.A_BOLD if e.state == 0 \
            else curses.color_pair(CP_DIM)
        # status==0 means start_response wasn't called yet: show a dash
        # so it's visibly distinct from a real status code.
        status_str = "-" if not e.status else str(e.status)
        line = (f"  {st:<6}  {fmt_seconds(elapsed):>9}  {e.pid:>7}  "
                f"{e.method:<7}  {status_str:>6}  "
                f"{(e.log_id or '-')[:24]:<24}  {e.url()}")
        safe_addstr(win, y, 0, line, attr)
        y += 1

    if y < height - 1:
        # Show a brief I/O footer for the top entry.
        if rows:
            _, _, top = rows[0]
            footer = (f"  top: cpu user={fmt_seconds(top.cpu_user_time)} "
                      f"sys={fmt_seconds(top.cpu_system_time)}   "
                      f"i/o in={fmt_bytes(top.input_bytes)}/{top.input_reads}r "
                      f"out={fmt_bytes(top.output_bytes)}/{top.output_writes}w")
            safe_addstr(win, height - 2, 0, footer, curses.color_pair(CP_DIM))


# --- Help overlay ------------------------------------------------------------


HELP_LINES = [
    "Keys:",
    "  o / 1   overview            p / 2   processes",
    "  w / 3   workers             l / 4   latency",
    "  s / 5   slow requests",
    "",
    "  space   pause/resume rendering   r   reset/clear (slow view)",
    "  + / -   change refresh rate      ?   toggle this help",
    "  < / >   change sort or window    [ / ]  cycle phase (latency)",
    "  f       cycle filters (group, slow state)",
    "  /       slow URL search (slow view; type then Enter; Esc clears)",
    "  q       quit",
]


def render_help(win) -> None:
    h, w = win.getmaxyx()
    box_w = max(60, max(len(line) for line in HELP_LINES) + 4)
    box_h = len(HELP_LINES) + 4
    y0 = max(2, (h - box_h) // 2)
    x0 = max(2, (w - box_w) // 2)
    for r in range(box_h):
        safe_addstr(win, y0 + r, x0, " " * box_w, curses.color_pair(CP_TAB))
    safe_addstr(win, y0, x0, " " * box_w, curses.color_pair(CP_HEADER) | curses.A_BOLD)
    safe_addstr(win, y0, x0 + 2, " mod_wsgi-telemetry top — help ",
                curses.color_pair(CP_HEADER) | curses.A_BOLD)
    for i, line in enumerate(HELP_LINES):
        safe_addstr(win, y0 + 2 + i, x0 + 2, line, curses.color_pair(CP_TAB))


# ---------------------------------------------------------------------------
# WebSocket client
# ---------------------------------------------------------------------------


async def ws_client(url: str, state: State, stop: asyncio.Event) -> None:
    """Connect, drain, reconnect on failure with backoff."""
    backoff = 1.0
    state.url = url
    while not stop.is_set():
        try:
            timeout = aiohttp.ClientTimeout(total=None, sock_connect=5, sock_read=None)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.ws_connect(url, heartbeat=30) as ws:
                    state.connected = True
                    state.last_error = ""
                    backoff = 1.0
                    async for msg in ws:
                        if msg.type == aiohttp.WSMsgType.TEXT:
                            try:
                                payload = json.loads(msg.data)
                            except json.JSONDecodeError:
                                continue
                            state.apply(payload)
                        elif msg.type in (aiohttp.WSMsgType.CLOSED,
                                          aiohttp.WSMsgType.ERROR):
                            break
                        if stop.is_set():
                            break
        except asyncio.CancelledError:
            break
        except Exception as e:
            state.last_error = f"{type(e).__name__}: {e}"
        state.connected = False
        if stop.is_set():
            break
        try:
            await asyncio.wait_for(stop.wait(), timeout=backoff)
            break
        except asyncio.TimeoutError:
            pass
        backoff = min(backoff * 2, 10.0)


# ---------------------------------------------------------------------------
# Curses setup + dispatch
# ---------------------------------------------------------------------------


def init_colors() -> None:
    if not curses.has_colors():
        return
    curses.start_color()
    try:
        curses.use_default_colors()
        bg = -1
    except curses.error:
        bg = curses.COLOR_BLACK
    curses.init_pair(CP_HEADER, curses.COLOR_BLACK, curses.COLOR_CYAN)
    curses.init_pair(CP_OK, curses.COLOR_GREEN, bg)
    curses.init_pair(CP_WARN, curses.COLOR_YELLOW, bg)
    curses.init_pair(CP_CRIT, curses.COLOR_RED, bg)
    curses.init_pair(CP_DIM, curses.COLOR_WHITE, bg)
    curses.init_pair(CP_BAR, curses.COLOR_CYAN, bg)
    curses.init_pair(CP_TAB, curses.COLOR_WHITE, curses.COLOR_BLUE)
    curses.init_pair(CP_TAB_ACTIVE, curses.COLOR_BLACK, curses.COLOR_WHITE)


class App:
    def __init__(self, stdscr, state: State, ui: UIState, stop: asyncio.Event,
                 *, no_color: bool) -> None:
        self.stdscr = stdscr
        self.state = state
        self.ui = ui
        self.stop = stop
        self.no_color = no_color
        self.search_mode = False
        self.search_buf = ""

    def handle_key(self, ch: int) -> None:
        ui = self.ui
        if self.search_mode:
            self._handle_search_key(ch)
            return
        if ch in (ord("q"), 27):  # q or ESC
            self.stop.set()
            return
        if ch == ord("?") or ch == ord("h"):
            ui.show_help = not ui.show_help
            return
        if ch == ord(" "):
            ui.paused = not ui.paused
            return
        if ch == ord("+"):
            ui.refresh_idx = max(0, ui.refresh_idx - 1)
            return
        if ch == ord("-"):
            ui.refresh_idx = min(len(REFRESH_RATES) - 1, ui.refresh_idx + 1)
            return
        if ch in VIEW_KEYS:
            ui.view = VIEW_KEYS[ch]
            return
        if ch == ord("<") or ch == ord(","):
            self._cycle_left()
            return
        if ch == ord(">") or ch == ord("."):
            self._cycle_right()
            return
        if ch == ord("[") and ui.view == "latency":
            ui.phase_idx = (ui.phase_idx - 1) % len(PHASES)
            return
        if ch == ord("]") and ui.view == "latency":
            ui.phase_idx = (ui.phase_idx + 1) % len(PHASES)
            return
        if ch == ord("f"):
            self._cycle_filter()
            return
        if ch == ord("r") and ui.view == "slow":
            ui.slow_search = ""
            ui.slow_state_filter = -1
            return
        if ch == ord("/") and ui.view == "slow":
            self.search_mode = True
            self.search_buf = ui.slow_search
            return

    def _handle_search_key(self, ch: int) -> None:
        if ch in (10, 13):
            self.ui.slow_search = self.search_buf
            self.search_mode = False
        elif ch == 27:
            self.search_mode = False
            self.search_buf = ""
            self.ui.slow_search = ""
        elif ch in (curses.KEY_BACKSPACE, 127, 8):
            self.search_buf = self.search_buf[:-1]
        elif 32 <= ch < 127:
            self.search_buf += chr(ch)

    def _cycle_left(self) -> None:
        ui = self.ui
        if ui.view in ("overview", "latency"):
            ui.window_idx = (ui.window_idx - 1) % len(WINDOW_CHOICES)
        elif ui.view == "processes":
            keys = ["rps", "cpu", "rss", "p95", "slow", "pid"]
            i = keys.index(ui.process_sort) if ui.process_sort in keys else 0
            ui.process_sort = keys[(i - 1) % len(keys)]
        elif ui.view == "slow":
            keys = ["elapsed", "pid", "method", "url"]
            i = keys.index(ui.slow_sort) if ui.slow_sort in keys else 0
            ui.slow_sort = keys[(i - 1) % len(keys)]

    def _cycle_right(self) -> None:
        ui = self.ui
        if ui.view in ("overview", "latency"):
            ui.window_idx = (ui.window_idx + 1) % len(WINDOW_CHOICES)
        elif ui.view == "processes":
            keys = ["rps", "cpu", "rss", "p95", "slow", "pid"]
            i = keys.index(ui.process_sort) if ui.process_sort in keys else 0
            ui.process_sort = keys[(i + 1) % len(keys)]
        elif ui.view == "slow":
            keys = ["elapsed", "pid", "method", "url"]
            i = keys.index(ui.slow_sort) if ui.slow_sort in keys else 0
            ui.slow_sort = keys[(i + 1) % len(keys)]

    def _cycle_filter(self) -> None:
        ui = self.ui
        if ui.view == "slow":
            seq = [-1, 0, 1]
            i = seq.index(ui.slow_state_filter) if ui.slow_state_filter in seq else 0
            ui.slow_state_filter = seq[(i + 1) % len(seq)]
            return
        groups = _process_groups(self.state)
        if not groups:
            ui.group_filter = None
            return
        cycle = [None] + groups
        try:
            i = cycle.index(ui.group_filter)
        except ValueError:
            i = 0
        ui.group_filter = cycle[(i + 1) % len(cycle)]

    def render(self) -> None:
        stdscr = self.stdscr
        stdscr.erase()
        h = _aggregate_header(self.state, self.ui)
        y0 = render_header(stdscr, self.state, self.ui, h)
        view = self.ui.view
        if view == "overview":
            render_overview(stdscr, self.state, self.ui, h, y0)
        elif view == "processes":
            render_processes(stdscr, self.state, self.ui, y0)
        elif view == "workers":
            render_workers(stdscr, self.state, self.ui, y0)
        elif view == "latency":
            render_latency(stdscr, self.state, self.ui, y0)
        elif view == "slow":
            render_slow(stdscr, self.state, self.ui, y0)

        # Footer.
        height, width = stdscr.getmaxyx()
        footer = self._footer_text()
        safe_addstr(stdscr, height - 1, 0, footer.ljust(width)[:width],
                    curses.color_pair(CP_TAB))
        if self.ui.show_help:
            render_help(stdscr)
        stdscr.noutrefresh()
        curses.doupdate()

    def _footer_text(self) -> str:
        if self.search_mode:
            return f" / search: {self.search_buf}_  (Enter=apply  Esc=cancel) "
        st = self.state
        if not st.connected:
            return f" disconnected ({st.last_error or 'connecting...'})  url={st.url} "
        age = time.monotonic() - st.last_message if st.last_message else 0
        return (f" connected to {st.url}  pids={len(st.processes)}  "
                f"slow={len(st.slow)}  rcvd={st.total_received}  "
                f"last_msg={age:.1f}s ago "
                f"{'PAUSED' if self.ui.paused else ''}")


async def run_app(stdscr, args, state: State, ui: UIState) -> int:
    init_colors() if not args.no_color else None
    curses.curs_set(0)
    stdscr.nodelay(True)
    stdscr.keypad(True)

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        try:
            loop.add_signal_handler(sig, stop.set)
        except (NotImplementedError, ValueError):
            pass

    ws_task = asyncio.create_task(ws_client(args.url, state, stop))
    app = App(stdscr, state, ui, stop, no_color=args.no_color)

    try:
        last_render = 0.0
        while not stop.is_set():
            # Drain all pending keys.
            while True:
                ch = stdscr.getch()
                if ch == -1:
                    break
                app.handle_key(ch)
            now = time.monotonic()
            if now - last_render >= ui.refresh and not ui.paused:
                app.render()
                last_render = now
            elif now - last_render >= ui.refresh:
                app.render()
                last_render = now
            await asyncio.sleep(0.05)
    finally:
        ws_task.cancel()
        try:
            await ws_task
        except (asyncio.CancelledError, Exception):
            pass

    return 0


def render_once_text(state: State, ui: UIState) -> str:
    """Plain-text snapshot for --once. No curses, no colors."""
    h = _aggregate_header(state, ui)
    lines = []
    pgroup = ui.group_filter or ",".join(_process_groups(state)) or "(any)"
    hostname = next(iter(state.processes.values())).hostname if state.processes else "-"
    lines.append(f"mod_wsgi-telemetry top  host={hostname}  group={pgroup}")
    lines.append(f"  rps:  now {h['rps_now']:.1f}   1m {h['rps_1m']:.1f}   "
                 f"10m {h['rps_10m']:.1f}   "
                 f"in {fmt_bytes(h['in_bps'])}/s  out {fmt_bytes(h['out_bps'])}/s")
    cap_total = h["threads_total"]
    cap_busy = h["busy"]
    frac = (cap_busy / cap_total) if cap_total else 0.0
    lines.append(f"  cap:  {cap_busy}/{cap_total} threads ({frac*100:.1f}%)   "
                 f"queue {fmt_seconds(h['queue_mean']) if h['queue_mean'] is not None else '-'}")
    lines.append(f"  cpu:  user {h['cpu_user']:.2f}  sys {h['cpu_sys']:.2f}   "
                 f"rss {fmt_bytes(h['rss_total'])} (max {fmt_bytes(h['rss_max'])})")
    # status==0 (no start_response, exception path) is folded into 5xx
    # on the C side; the percentages here are share of completed
    # requests in the latest interval. 1xx is a PEP 3333 tripwire and
    # only included in the line when it has fired.
    requests = h["interval_requests"]
    pct = lambda n: (n / requests * 100.0) if requests > 0 else 0.0
    s_parts = []
    if h["status_1xx"] > 0:
        s_parts.append(f"1xx {h['status_1xx']} (PEP 3333 violation)")
    s_parts.append(f"2xx {pct(h['status_2xx']):.1f}%")
    s_parts.append(f"3xx {pct(h['status_3xx']):.1f}%")
    s_parts.append(f"4xx {pct(h['status_4xx']):.1f}%")
    s_parts.append(f"5xx {pct(h['status_5xx']):.1f}%")
    lines.append("  stat: " + "  ".join(s_parts))
    lines.append(f"  lat:  p50 {fmt_seconds(h['p50'])}  "
                 f"p95 {fmt_seconds(h['p95'])}  p99 {fmt_seconds(h['p99'])}   "
                 f"min {fmt_seconds(h['min'])}  max {fmt_seconds(h['max'])}")
    lines.append(f"  slow: {h['active_slow']} active / {h['recent_slow']} 1m / "
                 f"{h['total_slow']} total")
    lines.append("")
    lines.append("processes:")
    rows = []
    for ps in state.processes.values():
        if ui.group_filter and ps.process_group != ui.group_filter:
            continue
        if not ps.samples:
            continue
        f = ps.samples[-1].get("fields", {})
        rows.append((
            ps.pid, ps.process_group or "-",
            int(f.get("request_threads_active") or 0),
            int(f.get("request_threads_maximum") or 0),
            float(f.get("request_throughput") or 0),
            float(f.get("cpu_utilization") or 0),
            int(f.get("memory_rss") or 0),
        ))
    rows.sort(key=lambda r: -r[4])
    lines.append(f"  {'PID':>7}  {'GROUP':<16}  {'THR':>9}  {'RPS':>7}  "
                 f"{'CPU':>6}  {'RSS':>9}")
    for pid, grp, act, mx, rps, cpu, rss in rows:
        lines.append(f"  {pid:>7}  {grp[:16]:<16}  {act:>4}/{mx:<4}  "
                     f"{rps:>7.1f}  {cpu:>6.2f}  {fmt_bytes(rss):>9}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Terminal monitor for mod_wsgi telemetry."
    )
    ap.add_argument("--url", default=os.environ.get("MOD_WSGI_TELEMETRY_URL", DEFAULT_URL),
                    help=f"WebSocket URL of the telemetry server (default: {DEFAULT_URL})")
    ap.add_argument("--refresh", type=float, default=1.0,
                    help="Render refresh interval in seconds (default: 1.0)")
    ap.add_argument("--view", choices=VIEWS, default="overview",
                    help="Initial view (default: overview)")
    ap.add_argument("--group", default=None,
                    help="Filter to a single process group")
    ap.add_argument("--no-color", action="store_true",
                    help="Disable ANSI colour")
    ap.add_argument("--once", action="store_true",
                    help="Render one frame to stdout and exit (scriptable)")
    ap.add_argument("--once-timeout", type=float, default=3.0,
                    help="Max seconds to wait for the snapshot in --once mode")
    ap.add_argument("--log-file", default=None,
                    help="Write debug log to this file (curses hides stderr)")
    args = ap.parse_args(argv)

    if args.log_file:
        logging.basicConfig(filename=args.log_file, level=logging.DEBUG,
                            format="%(asctime)s %(levelname)s %(name)s %(message)s")

    state = State()
    ui = UIState(view=args.view, group_filter=args.group)
    # Snap refresh to the closest preset so the cycler stays consistent.
    ui.refresh_idx = min(
        range(len(REFRESH_RATES)),
        key=lambda i: abs(REFRESH_RATES[i] - args.refresh),
    )

    if args.once:
        return _run_once(args, state, ui)

    return curses.wrapper(_curses_main, args, state, ui)


def _curses_main(stdscr, args, state, ui) -> int:
    return asyncio.run(run_app(stdscr, args, state, ui))


def _run_once(args, state: State, ui: UIState) -> int:
    async def grab() -> int:
        stop = asyncio.Event()
        ws_task = asyncio.create_task(ws_client(args.url, state, stop))
        deadline = time.monotonic() + args.once_timeout
        try:
            while time.monotonic() < deadline:
                if state.last_message:
                    # Wait one extra tick to catch any in-flight live update.
                    await asyncio.sleep(0.1)
                    break
                await asyncio.sleep(0.05)
            sys.stdout.write(render_once_text(state, ui) + "\n")
            return 0 if state.last_message else 2
        finally:
            stop.set()
            ws_task.cancel()
            try:
                await ws_task
            except (asyncio.CancelledError, Exception):
                pass

    return asyncio.run(grab())


if __name__ == "__main__":
    sys.exit(main())
