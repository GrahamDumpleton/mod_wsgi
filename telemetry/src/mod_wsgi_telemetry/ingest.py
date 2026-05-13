"""Async datagram receiver + rolling per-process window.

Listens on a UNIX SOCK_DGRAM socket for TLV samples, decodes them, and
keeps a bounded history per PID so connecting UI clients can fetch
recent state immediately without waiting for the next tick.

Remote (IPv4 UDP) listeners are not supported — telemetry is intended
for a co-located ingester so MTU / IP-fragmentation / packet-loss are
non-concerns. The reporter is allowed to emit datagrams that exceed
the Ethernet MTU as a result.

Emits each decoded sample on an asyncio broadcast queue for WebSocket
clients to pick up.
"""

from __future__ import annotations

import asyncio
import logging
import os
import socket
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Iterable

from .wire import Sample, decode

log = logging.getLogger(__name__)


def parse_listen(spec: str) -> tuple[int, str]:
    """Return (family, bind_path) for a UNIX SOCK_DGRAM target."""
    if spec.startswith("unix:"):
        return socket.AF_UNIX, spec[len("unix:"):]
    raise ValueError(
        f"unknown scheme {spec!r}: expected 'unix:/path' "
        f"(remote 'udp:host:port' targets are no longer supported)"
    )


def open_socket(spec: str) -> socket.socket:
    family, addr = parse_listen(spec)
    sock = socket.socket(family, socket.SOCK_DGRAM)

    if os.path.exists(addr):
        os.unlink(addr)
    sock.bind(addr)
    os.chmod(addr, 0o666)

    sock.setblocking(False)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2 * 1024 * 1024)
    except OSError:
        pass
    return sock


@dataclass
class ProcessState:
    """Rolling window of samples for one PID."""
    pid: int
    hostname: str = ""
    process_group: str = ""
    # Build/runtime identity. Emitted by the daemon once at process
    # start (or on every sample; the ingester doesn't care) and
    # latched here so a mid-stream client reconnect still sees the
    # "who is this" banner via the snapshot payload, even if the
    # rolling sample window no longer carries the identity TLVs.
    mod_wsgi_version: str = ""
    python_version: str = ""
    apache_version: str = ""
    mpm_name: str = ""
    # Apache parent pid, latched from process_started. Lets the UI
    # group sibling daemon processes under their parent.
    process_parent_pid: int = 0
    # Telemetry reporter's tick interval in seconds, as reported by the
    # process itself on each KIND_REQUEST sample. Used to size the
    # slow-request TTLs — a reporter ticking every 10 s needs a longer
    # TTL than the default 5 s floor so heartbeats aren't aged out
    # between ticks.
    sample_period: float = 1.0
    samples: deque = field(default_factory=lambda: deque(maxlen=600))
    last_seq: int = 0
    drops: int = 0
    last_seen: float = 0.0


@dataclass
class SlowEntry:
    """One slow request as currently known to the ingester.

    Active heartbeats replace earlier active records for the same key; a
    completed record marks the entry final (its duration is the end-of-
    request total). last_seen is the wall-monotonic arrival time, used for
    TTL age-out so requests from processes that died mid-flight don't
    linger as "active" forever.

    I/O counters are final at completion; for an active record they
    are the partial values captured at scan time (the adapter may yet
    read or write more before the request completes).
    """
    pid: int
    thread_id: int
    # Apache child worker pid that accepted the request. In embedded
    # mode this is the same process as pid (Apache child runs the
    # WSGI app directly). In daemon mode pid is the daemon process
    # and server_pid is the Apache child that proxied the request.
    server_pid: int
    log_id: str
    method: str
    scheme: str
    hostname: str
    script_name: str
    path_info: str
    start_stamp: float          # seconds since epoch
    duration: float             # seconds
    state: int                  # 0 = active, 1 = completed
    # Network identity. peer_ip is post-trusted-proxy resolution, so
    # reflects the real client when X-Forwarded-For handling is
    # configured. protocol is "HTTP/1.1" / "HTTP/2.0". user_agent
    # is empty unless the operator opted in via
    # WSGIMetricsOptions +CaptureUserAgent.
    peer_ip: str = ""
    protocol: str = ""
    user_agent: str = ""
    input_bytes: int = 0
    input_reads: int = 0
    output_bytes: int = 0
    output_writes: int = 0
    cpu_user_time: float = 0.0
    cpu_system_time: float = 0.0
    # Per-phase timing breakdown (seconds). server is Apache
    # request arrival to handed off to daemon (or to application_start
    # in embedded mode); queue is daemon connect to worker pickup;
    # daemon is worker pickup to WSGI callable invoked; application
    # is the WSGI callable elapsed. queue and daemon are 0 in
    # embedded mode. application is partial for active records still
    # inside the callable; pre-application active records report 0
    # for application and a partial daemon (or server) so the user
    # can see where time is going.
    server_time: float = 0.0
    queue_time: float = 0.0
    daemon_time: float = 0.0
    application_time: float = 0.0
    # GIL-wait pressure indicator. Sum of waits at every instrumented
    # re-acquire site reached during this request, plus the initial
    # sub-interp GIL acquire. Cross-cutting overlap, not a phase
    # addend. Cannot see waits inside the application's own C
    # extensions, so it surfaces as a partial pressure indicator.
    gil_wait_time: float = 0.0
    gil_wait_count: int = 0
    # I/O time overlap indicators for this request. input_read_time is
    # the total time spent inside wsgi.input.read*; output_write_time
    # is the total time spent in the adapter's output path
    # (start_response / write / yield-to-Apache). Cross-cutting
    # overlap, not a phase addend. output_write_time is "adapter
    # handoff" time, not client-receive time: Apache may buffer and
    # async-flush past mod_wsgi's view. See the wire.py field
    # comment for the full caveat.
    input_read_time: float = 0.0
    output_write_time: float = 0.0
    # Concurrency context — wsgi_active_requests including this one
    # at slot claim and at completion. active_at_completion is 0 for
    # active records by definition (the request hasn't finished).
    # Used together with the per-process request_threads_maximum
    # from the periodic stream to render an "n / max" saturation
    # indicator on the slow-record detail panel.
    active_at_start: int = 0
    active_at_completion: int = 0
    status: int = 0            # 0 = not yet known, else final WSGI status
    last_seen: float = 0.0

    def to_dict(self) -> dict:
        return {
            "pid": self.pid,
            "thread_id": self.thread_id,
            "server_pid": self.server_pid,
            "log_id": self.log_id,
            "method": self.method,
            "scheme": self.scheme,
            "hostname": self.hostname,
            "script_name": self.script_name,
            "path_info": self.path_info,
            "peer_ip": self.peer_ip,
            "protocol": self.protocol,
            "user_agent": self.user_agent,
            "start_stamp": self.start_stamp,
            "duration": self.duration,
            "state": self.state,
            "input_bytes": self.input_bytes,
            "input_reads": self.input_reads,
            "output_bytes": self.output_bytes,
            "output_writes": self.output_writes,
            "cpu_user_time": self.cpu_user_time,
            "cpu_system_time": self.cpu_system_time,
            "server_time": self.server_time,
            "queue_time": self.queue_time,
            "daemon_time": self.daemon_time,
            "application_time": self.application_time,
            "gil_wait_time": self.gil_wait_time,
            "gil_wait_count": self.gil_wait_count,
            "input_read_time": self.input_read_time,
            "output_write_time": self.output_write_time,
            "active_at_start": self.active_at_start,
            "active_at_completion": self.active_at_completion,
            "status": self.status,
        }


@dataclass
class LifecycleEvent:
    """One process_started / process_stopping / process_stopped record.

    Stored in a bounded ingester-side deque so reconnecting clients see
    recent restart history without waiting for the next event. The
    frontend renders STOPPING events as chart markers; STARTED and
    STOPPED feed the (future) process-lifetime panel and the
    forensics-style restart event log.
    """
    kind: str               # "process_started" | "process_stopping" | "process_stopped"
    pid: int
    stamp: float            # seconds since epoch
    hostname: str = ""
    process_group: str = ""
    process_parent_pid: int = 0     # STARTED only
    shutdown_reason: str = ""       # STOPPING / STOPPED
    process_uptime: float = 0.0     # STOPPED only — seconds
    lifetime_request_count: int = 0  # STOPPED only
    active_requests_at_decision: int = 0  # STOPPING only
    active_requests_at_exit: int = 0      # STOPPED only
    graceful_drain: int = 0          # STOPPED only — 1 if drain completed cleanly

    def to_dict(self) -> dict:
        return {
            "kind": self.kind,
            "pid": self.pid,
            "stamp": self.stamp,
            "hostname": self.hostname,
            "process_group": self.process_group,
            "process_parent_pid": self.process_parent_pid,
            "shutdown_reason": self.shutdown_reason,
            "process_uptime": self.process_uptime,
            "lifetime_request_count": self.lifetime_request_count,
            "active_requests_at_decision": self.active_requests_at_decision,
            "active_requests_at_exit": self.active_requests_at_exit,
            "graceful_drain": self.graceful_drain,
        }


class Ingester:
    """Owns the listening socket and all per-process state."""

    STALE_SECONDS = 300  # drop processes we haven't heard from in 5 min

    # Floor values for slow-request *storage* TTLs. Effective TTL per
    # entry scales with the reporting process's telemetry interval
    # (see _gc_slow): active = max(FLOOR, 3 * sample_period), completed
    # = max(FLOOR, 5 * sample_period), so a 10 s reporter interval
    # doesn't drop entries between heartbeats.
    #
    # Active records still age out fast so a worker that died mid-
    # request doesn't leave a ghost row pinned forever.
    #
    # Completed records are kept long enough to support drill-down
    # from the Capacity heatmap (whose visible window can outlive the
    # 15 s display TTL the UI table uses). Initially set to match the
    # client's SAMPLE_RETENTION_SEC (10 minutes) — kept as a separate
    # constant so it can be adjusted independently from sample
    # retention if the trade-off ever changes.
    SLOW_ACTIVE_TTL_SECONDS = 5.0
    SLOW_COMPLETED_TTL_SECONDS = 600.0

    # Lifecycle events kept in a bounded ring so a reconnecting client
    # sees recent restart history without waiting for the next event.
    # Sized to comfortably outlive the chart's default rolling window
    # (10 minutes) even on a process group that restarts aggressively.
    LIFECYCLE_RING_SIZE = 500

    def __init__(self, listen_spec: str, *, max_subscribers: int = 64) -> None:
        self.listen_spec = listen_spec
        self.sock: socket.socket | None = None
        self.processes: dict[int, ProcessState] = {}
        self.slow_requests: dict[tuple, SlowEntry] = {}
        self.lifecycle_events: deque[LifecycleEvent] = deque(
            maxlen=self.LIFECYCLE_RING_SIZE
        )
        self.subscribers: set[asyncio.Queue] = set()
        self.max_subscribers = max_subscribers
        self.decode_errors = 0
        self.total_received = 0

    async def run(self) -> None:
        self.sock = open_socket(self.listen_spec)
        loop = asyncio.get_running_loop()
        log.info("listening on %s", self.listen_spec)
        try:
            while True:
                data = await loop.sock_recv(self.sock, 65536)
                self._handle(data)
        except asyncio.CancelledError:
            pass
        finally:
            if self.sock:
                self.sock.close()

    def _handle(self, data: bytes) -> None:
        self.total_received += 1
        try:
            sample = decode(data)
        except Exception as e:
            self.decode_errors += 1
            log.warning("decode error: %s (len=%d)", e, len(data))
            return

        # Slow-request records are a separate stream. They don't share the
        # per-process rolling sample window — they feed into slow_requests.
        if sample.kind_name == "slow_request":
            self._handle_slow(sample)
            self._gc_slow()
            self._gc_stale()
            return

        # Lifecycle events feed a separate ring buffer; the periodic
        # sample window doesn't carry them.
        if sample.kind_name in (
            "process_started", "process_stopping", "process_stopped"
        ):
            self._handle_lifecycle(sample)
            self._gc_stale()
            return

        state = self.processes.get(sample.pid)
        if state is None:
            state = ProcessState(pid=sample.pid)
            self.processes[sample.pid] = state

        if state.last_seq and sample.seq > state.last_seq + 1:
            state.drops += sample.seq - state.last_seq - 1

        state.last_seq = sample.seq
        state.last_seen = time.monotonic()
        state.samples.append(sample)

        def _latch_str(field_name: str, attr: str) -> None:
            v = sample.fields.get(field_name)
            if isinstance(v, bytes):
                setattr(state, attr, v.decode("utf-8", errors="replace"))

        _latch_str("hostname", "hostname")
        _latch_str("process_group", "process_group")
        _latch_str("mod_wsgi_version", "mod_wsgi_version")
        _latch_str("python_version", "python_version")
        _latch_str("apache_version", "apache_version")
        _latch_str("mpm_name", "mpm_name")

        ppid = sample.fields.get("process_parent_pid")
        if isinstance(ppid, int) and ppid > 0:
            state.process_parent_pid = ppid

        sp = sample.fields.get("sample_period")
        if isinstance(sp, (int, float)) and sp > 0:
            state.sample_period = float(sp)

        self._broadcast(sample)
        self._gc_slow()
        self._gc_stale()

    def _handle_lifecycle(self, sample: Sample) -> None:
        """Record a STARTED / STOPPING / STOPPED event.

        STARTED also seeds / refreshes the per-process identity so a
        late-joining client can render the process even if the periodic
        stream hasn't begun yet for this pid. STOPPING and STOPPED only
        carry the trimmed identity (hostname, group) since the consumer
        already knows the process from STARTED + the periodic stream.
        """
        f = sample.fields

        def _s(name: str) -> str:
            v = f.get(name)
            if isinstance(v, bytes):
                return v.decode("utf-8", errors="replace")
            return ""

        ev = LifecycleEvent(
            kind=sample.kind_name,
            pid=sample.pid,
            stamp=sample.stamp,
            hostname=_s("hostname"),
            process_group=_s("process_group"),
            process_parent_pid=int(f.get("process_parent_pid") or 0),
            shutdown_reason=_s("shutdown_reason"),
            process_uptime=float(f.get("process_uptime") or 0.0),
            lifetime_request_count=int(f.get("lifetime_request_count") or 0),
            active_requests_at_decision=int(
                f.get("active_requests_at_decision") or 0),
            active_requests_at_exit=int(
                f.get("active_requests_at_exit") or 0),
            graceful_drain=int(f.get("graceful_drain") or 0),
        )
        self.lifecycle_events.append(ev)

        # STARTED is the canonical place to latch the static identity
        # banner and the parent pid. Create the ProcessState if the
        # periodic stream hasn't arrived yet so the sidebar shows the
        # process the moment it announces itself.
        if sample.kind_name == "process_started":
            state = self.processes.get(sample.pid)
            if state is None:
                state = ProcessState(pid=sample.pid)
                self.processes[sample.pid] = state
            state.last_seen = time.monotonic()
            if ev.hostname:
                state.hostname = ev.hostname
            if ev.process_group:
                state.process_group = ev.process_group
            if ev.process_parent_pid:
                state.process_parent_pid = ev.process_parent_pid
            for name in ("mod_wsgi_version", "python_version",
                         "apache_version", "mpm_name"):
                v = _s(name)
                if v:
                    setattr(state, name, v)

        self._enqueue_all({
            "type": "lifecycle",
            "event": ev.to_dict(),
        })

    def _handle_slow(self, sample: Sample) -> None:
        f = sample.fields

        def _s(name: str) -> str:
            v = f.get(name)
            if isinstance(v, bytes):
                return v.decode("utf-8", errors="replace")
            return ""

        log_id = _s("slow_log_id")
        thread_id = int(f.get("slow_thread_id") or 0)
        start_stamp = float(f.get("slow_start_stamp") or 0.0)

        # Prefer Apache's per-request log_id as correlation key; fall back
        # to a (pid, thread, start) tuple when mod_unique_id isn't loaded.
        if log_id:
            key: tuple = (sample.pid, log_id)
        else:
            key = (sample.pid, thread_id, start_stamp)

        entry = SlowEntry(
            pid=sample.pid,
            thread_id=thread_id,
            server_pid=int(f.get("slow_server_pid") or 0),
            log_id=log_id,
            method=_s("slow_method"),
            scheme=_s("slow_scheme"),
            hostname=_s("slow_hostname"),
            script_name=_s("slow_script_name"),
            path_info=_s("slow_path_info"),
            peer_ip=_s("slow_peer_ip"),
            protocol=_s("slow_protocol"),
            user_agent=_s("slow_user_agent"),
            start_stamp=start_stamp,
            duration=float(f.get("slow_duration") or 0.0),
            state=int(f.get("slow_record_state") or 0),
            input_bytes=int(f.get("slow_input_bytes") or 0),
            input_reads=int(f.get("slow_input_reads") or 0),
            output_bytes=int(f.get("slow_output_bytes") or 0),
            output_writes=int(f.get("slow_output_writes") or 0),
            cpu_user_time=float(f.get("slow_cpu_user_time") or 0.0),
            cpu_system_time=float(f.get("slow_cpu_system_time") or 0.0),
            server_time=float(f.get("slow_server_time") or 0.0),
            queue_time=float(f.get("slow_queue_time") or 0.0),
            daemon_time=float(f.get("slow_daemon_time") or 0.0),
            application_time=float(f.get("slow_application_time") or 0.0),
            gil_wait_time=float(f.get("slow_gil_wait_time") or 0.0),
            gil_wait_count=int(f.get("slow_gil_wait_count") or 0),
            input_read_time=float(f.get("slow_input_read_time") or 0.0),
            output_write_time=float(f.get("slow_output_write_time") or 0.0),
            active_at_start=int(f.get("slow_active_at_start") or 0),
            active_at_completion=int(f.get("slow_active_at_completion") or 0),
            status=int(f.get("slow_status") or 0),
            last_seen=time.monotonic(),
        )
        self.slow_requests[key] = entry

        self._enqueue_all({
            "type": "slow_request",
            "key": list(key),
            "entry": entry.to_dict(),
            "stamp": sample.stamp,
        })

    def _broadcast(self, sample: Sample) -> None:
        self._enqueue_all(self._sample_to_dict(sample))

    def _enqueue_all(self, payload: dict) -> None:
        for q in list(self.subscribers):
            try:
                q.put_nowait(payload)
            except asyncio.QueueFull:
                # Slow consumer — drop the oldest to stay bounded.
                try:
                    q.get_nowait()
                    q.put_nowait(payload)
                except Exception:
                    pass

    def _gc_stale(self) -> None:
        now = time.monotonic()
        stale = [
            pid for pid, st in self.processes.items()
            if now - st.last_seen > self.STALE_SECONDS
        ]
        for pid in stale:
            log.info("gc: dropping stale pid=%d", pid)
            self.processes.pop(pid, None)

    def clear_slow_requests(self) -> None:
        """Drop completed history plus any active record GC would also drop.

        Triggered by the Slow requests tab's Clear button. Drops every
        completed entry outright and every active entry whose pid has died
        or whose last_seen is already past the active TTL — so the table
        snaps to "only requests the daemon is still actively heart-beating
        about". Live in-flight rows are preserved.
        """
        now = time.monotonic()
        live_pids = set(self.processes)
        kept: dict[tuple, SlowEntry] = {}
        for key, entry in self.slow_requests.items():
            if entry.state == 1:
                continue
            if entry.pid not in live_pids:
                continue
            proc = self.processes.get(entry.pid)
            sp = proc.sample_period if proc and proc.sample_period > 0 else 1.0
            ttl = max(self.SLOW_ACTIVE_TTL_SECONDS, 3.0 * sp)
            if now - entry.last_seen > ttl:
                continue
            kept[key] = entry
        self.slow_requests = kept
        self._enqueue_all({
            "type": "slow_clear",
            "kept": [
                {"key": list(k), "entry": e.to_dict()}
                for k, e in kept.items()
            ],
        })

    def _gc_slow(self) -> None:
        """Age out slow-request entries the reporter has stopped updating.

        Active entries disappear quickly so a worker that was killed mid-
        request doesn't leave a ghost row. Completed entries linger so a
        user can still see recently-finished slow requests when they open
        the UI. Both TTLs scale with the reporting process's telemetry
        interval: a reporter ticking every 10 s only emits heartbeats
        every 10 s, so a 5 s floor would flicker rows in and out — we
        bump TTL to 3x the sample period in that case. Also drops all
        entries for processes that have aged out of self.processes so
        the list stays in sync with the sidebar.
        """
        if not self.slow_requests:
            return
        now = time.monotonic()
        drop = []
        live_pids = set(self.processes)
        for key, entry in self.slow_requests.items():
            if entry.pid not in live_pids:
                drop.append(key)
                continue
            proc = self.processes.get(entry.pid)
            sp = proc.sample_period if proc and proc.sample_period > 0 else 1.0
            if entry.state == 1:
                ttl = max(self.SLOW_COMPLETED_TTL_SECONDS, 5.0 * sp)
            else:
                ttl = max(self.SLOW_ACTIVE_TTL_SECONDS, 3.0 * sp)
            if now - entry.last_seen > ttl:
                drop.append(key)
        for key in drop:
            self.slow_requests.pop(key, None)

    # --- WebSocket client API -------------------------------------------------

    def subscribe(self) -> asyncio.Queue:
        if len(self.subscribers) >= self.max_subscribers:
            raise RuntimeError("too many subscribers")
        q: asyncio.Queue = asyncio.Queue(maxsize=256)
        self.subscribers.add(q)
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        self.subscribers.discard(q)

    def snapshot(self) -> dict:
        """Return the full current rolling state for a newly-connected client."""
        return {
            "type": "snapshot",
            "processes": [
                {
                    "pid": st.pid,
                    "hostname": st.hostname,
                    "process_group": st.process_group,
                    "mod_wsgi_version": st.mod_wsgi_version,
                    "python_version": st.python_version,
                    "apache_version": st.apache_version,
                    "mpm_name": st.mpm_name,
                    "process_parent_pid": st.process_parent_pid,
                    "last_seq": st.last_seq,
                    "drops": st.drops,
                    "samples": [self._sample_to_dict(s) for s in st.samples],
                }
                for st in self.processes.values()
            ],
            "slow_requests": [
                {"key": list(k), "entry": e.to_dict()}
                for k, e in self.slow_requests.items()
            ],
            "lifecycle_events": [ev.to_dict() for ev in self.lifecycle_events],
            "total_received": self.total_received,
            "decode_errors": self.decode_errors,
        }

    @staticmethod
    def _sample_to_dict(sample: Sample) -> dict:
        return {
            "type": "sample",
            "kind": sample.kind_name,
            "pid": sample.pid,
            "seq": sample.seq,
            "stamp": sample.stamp,
            "fields": {
                k: (v.decode("utf-8", errors="replace") if isinstance(v, bytes) else v)
                for k, v in sample.fields.items()
            },
        }
