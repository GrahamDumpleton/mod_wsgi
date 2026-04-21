"""Async datagram receiver + rolling per-process window.

Listens on a UNIX or UDP datagram socket for TLV samples, decodes them,
and keeps a bounded history per PID so connecting UI clients can fetch
recent state immediately without waiting for the next tick.

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


def parse_listen(spec: str) -> tuple[int, tuple | str]:
    """Return (family, bind_addr)."""
    if spec.startswith("unix:"):
        return socket.AF_UNIX, spec[len("unix:"):]
    if spec.startswith("udp:"):
        rest = spec[len("udp:"):]
        host, _, port = rest.rpartition(":")
        if not host or not port:
            raise ValueError(f"bad udp listen spec {spec!r}")
        return socket.AF_INET, (host, int(port))
    raise ValueError(f"unknown scheme {spec!r}: expected unix: or udp:")


def open_socket(spec: str) -> socket.socket:
    family, addr = parse_listen(spec)
    sock = socket.socket(family, socket.SOCK_DGRAM)

    if family == socket.AF_UNIX:
        if os.path.exists(addr):
            os.unlink(addr)
        sock.bind(addr)
        os.chmod(addr, 0o666)
    else:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(addr)

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
    daemon_group: str = ""
    samples: deque = field(default_factory=lambda: deque(maxlen=600))
    last_seq: int = 0
    drops: int = 0
    last_seen: float = 0.0


class Ingester:
    """Owns the listening socket and all per-process state."""

    STALE_SECONDS = 300  # drop processes we haven't heard from in 5 min

    def __init__(self, listen_spec: str, *, max_subscribers: int = 64) -> None:
        self.listen_spec = listen_spec
        self.sock: socket.socket | None = None
        self.processes: dict[int, ProcessState] = {}
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

        state = self.processes.get(sample.pid)
        if state is None:
            state = ProcessState(pid=sample.pid)
            self.processes[sample.pid] = state

        if state.last_seq and sample.seq > state.last_seq + 1:
            state.drops += sample.seq - state.last_seq - 1

        state.last_seq = sample.seq
        state.last_seen = time.monotonic()
        state.samples.append(sample)

        hostname = sample.fields.get("hostname")
        if isinstance(hostname, bytes):
            state.hostname = hostname.decode("utf-8", errors="replace")
        group = sample.fields.get("daemon_group")
        if isinstance(group, bytes):
            state.daemon_group = group.decode("utf-8", errors="replace")

        self._broadcast(sample)
        self._gc_stale()

    def _broadcast(self, sample: Sample) -> None:
        payload = self._sample_to_dict(sample)
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
                    "daemon_group": st.daemon_group,
                    "last_seq": st.last_seq,
                    "drops": st.drops,
                    "samples": [self._sample_to_dict(s) for s in st.samples],
                }
                for st in self.processes.values()
            ],
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
            "stamp_us": sample.stamp_us,
            "fields": {
                k: (v.decode("utf-8", errors="replace") if isinstance(v, bytes) else v)
                for k, v in sample.fields.items()
            },
        }
