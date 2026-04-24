"""TLV wire format decoder for mod_wsgi telemetry samples.

This file is the Python-side mirror of src/server/wsgi_telemetry.h on the
mod_wsgi C side. Field IDs and type tags must stay in sync. Once the C
header is committed, this table should be regenerated from it.

Wire layout:

  fixed header (24 bytes, little-endian):
    magic     uint32   b'WSGI'
    version   uint8
    kind      uint8    1=process, 2=request, 3=server, 4=slow_request, 10+ events
    flags     uint16
    pid       uint32
    seq       uint32   monotonic per process, drop detection
    stamp_us  uint64   microseconds since epoch

  then repeated TLV records until the end of the datagram:
    id        uint16
    type      uint8    one of T_U64, T_F64, T_I64, T_BYTES, T_I32_ARRAY
    [len      uint16]  only for BYTES / I32_ARRAY
    value     per type
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Any

MAGIC = b"WSGI"

# Kind codes
KIND_PROCESS = 1
KIND_REQUEST = 2
KIND_SERVER = 3
KIND_SLOW_REQUEST = 4

KIND_NAMES = {
    KIND_PROCESS: "process_metrics",
    KIND_REQUEST: "request_metrics",
    KIND_SERVER: "server_metrics",
    KIND_SLOW_REQUEST: "slow_request",
}

# Type tags
T_U64 = 0x01
T_F64 = 0x02
T_I64 = 0x03
T_BYTES = 0x04
T_I32_ARRAY = 0x05

# Field ID table. Mirrors wsgi_telemetry.h. Append-only; never reuse IDs.
# When the C header is committed, a codegen script should replace this
# block. Field IDs below are tentative pending the C-side implementation.
FIELDS = {
    # Identity
    1: "hostname",
    2: "process_group",

    # Interval / counting
    10: "sample_period",
    11: "request_count",
    12: "request_throughput",
    13: "capacity_utilization",

    # CPU (from wsgi_request_metrics — interval rates)
    20: "cpu_user_utilization",
    21: "cpu_system_utilization",
    22: "cpu_utilization",

    # CPU (from wsgi_process_metrics — cumulative seconds)
    25: "cpu_user_time",
    26: "cpu_system_time",
    27: "cpu_time",

    # Memory
    30: "memory_rss",
    31: "memory_max_rss",

    # Threads
    40: "request_threads_maximum",
    41: "request_threads_started",
    42: "request_threads_active",

    # Average per-request times (seconds)
    50: "server_time",
    51: "queue_time",
    52: "daemon_time",
    53: "application_time",

    # Bucket arrays (16 slots, log2 from 5 ms)
    60: "server_time_buckets",
    61: "queue_time_buckets",
    62: "daemon_time_buckets",
    63: "application_time_buckets",

    # Per-slot capacity signals. One entry per worker thread, carried as
    # i32 arrays whose length matches the emitting process's live
    # request_threads_maximum. Field 64 was historically reserved as
    # "request_threads_buckets"; its semantics (completed-request count
    # per slot) are preserved under the clearer name slot_request_count.
    64: "slot_request_count",
    90: "slot_busy_time_us",
    91: "slot_cpu_time_us",
    92: "slot_current_elapsed_ms",
    93: "slot_max_duration_ms",

    # Total response time = server + queue + daemon + application, summed
    # per request and bucketed. What the caller actually experienced,
    # short of the external Apache accept-queue wait (not observable from
    # within the worker).
    94: "request_time_buckets",

    # Per-interval request I/O totals. Drained from the adapter's
    # InputObject.bytes/reads and AdapterObject.output_length/output_writes
    # at end-of-request; in-flight requests don't contribute until they
    # finish.
    70: "input_bytes_total",
    71: "input_reads_total",
    72: "output_bytes_total",
    73: "output_writes_total",

    # Slow-request fields (only present in KIND_SLOW_REQUEST datagrams).
    # Identity (hostname, process_group) is keyed per pid from the
    # accompanying KIND_REQUEST stream, so it is not repeated here.
    80: "slow_state",            # 0 = active, 1 = completed
    81: "slow_start_stamp_us",
    82: "slow_duration_us",
    83: "slow_thread_id",
    84: "slow_log_id",
    85: "slow_method",
    86: "slow_scheme",
    87: "slow_hostname",
    88: "slow_script_name",
    89: "slow_path_info",

    # Per-slow-request I/O. Final values for completed records, partial
    # for active records (adapter may yet read or write more).
    95: "slow_input_bytes",
    96: "slow_input_reads",
    97: "slow_output_bytes",
    98: "slow_output_writes",
}

# Reverse map for encoders / tests.
FIELD_IDS = {name: fid for fid, name in FIELDS.items()}


_HDR = struct.Struct("<4sBBHIIQ")
_TLV_HDR = struct.Struct("<HB")
_U16 = struct.Struct("<H")
_U64 = struct.Struct("<Q")
_I64 = struct.Struct("<q")
_F64 = struct.Struct("<d")


@dataclass
class Sample:
    version: int
    kind: int
    pid: int
    seq: int
    stamp_us: int
    fields: dict[str, Any]

    @property
    def kind_name(self) -> str:
        return KIND_NAMES.get(self.kind, f"kind{self.kind}")


class DecodeError(ValueError):
    pass


def decode(buf: bytes | memoryview) -> Sample:
    """Decode one TLV datagram into a Sample.

    Unknown field IDs are kept under a synthetic name like "id42" so
    nothing is silently dropped during wire-format evolution.
    """
    if len(buf) < _HDR.size:
        raise DecodeError(f"datagram too short: {len(buf)} bytes")

    magic, version, kind, _flags, pid, seq, stamp = _HDR.unpack_from(buf, 0)
    if magic != MAGIC:
        raise DecodeError(f"bad magic {magic!r}")

    off = _HDR.size
    fields: dict[str, Any] = {}
    while off < len(buf):
        if len(buf) - off < _TLV_HDR.size:
            raise DecodeError(f"truncated TLV header at offset {off}")
        fid, ftype = _TLV_HDR.unpack_from(buf, off)
        off += _TLV_HDR.size

        if ftype == T_U64:
            (value,) = _U64.unpack_from(buf, off)
            off += 8
        elif ftype == T_F64:
            (value,) = _F64.unpack_from(buf, off)
            off += 8
        elif ftype == T_I64:
            (value,) = _I64.unpack_from(buf, off)
            off += 8
        elif ftype == T_BYTES:
            (n,) = _U16.unpack_from(buf, off)
            off += 2
            value = bytes(buf[off:off + n])
            off += n
        elif ftype == T_I32_ARRAY:
            (n,) = _U16.unpack_from(buf, off)
            off += 2
            value = list(struct.unpack_from(f"<{n}i", buf, off))
            off += n * 4
        else:
            raise DecodeError(
                f"unknown type tag 0x{ftype:02x} at offset {off - 1}"
            )

        name = FIELDS.get(fid, f"id{fid}")
        fields[name] = value

    return Sample(
        version=version,
        kind=kind,
        pid=pid,
        seq=seq,
        stamp_us=stamp,
        fields=fields,
    )


def encode(sample: Sample) -> bytes:
    """Encode a Sample back to TLV bytes. Used by tests and simulate.py."""
    out = bytearray(
        _HDR.pack(
            MAGIC,
            sample.version,
            sample.kind,
            0,
            sample.pid,
            sample.seq,
            sample.stamp_us,
        )
    )
    for name, value in sample.fields.items():
        fid = FIELD_IDS.get(name)
        if fid is None:
            if name.startswith("id"):
                fid = int(name[2:])
            else:
                raise KeyError(f"no field id assigned for {name!r}")

        if isinstance(value, float):
            out += _TLV_HDR.pack(fid, T_F64) + _F64.pack(value)
        elif isinstance(value, bool):
            out += _TLV_HDR.pack(fid, T_U64) + _U64.pack(int(value))
        elif isinstance(value, int):
            if value < 0:
                out += _TLV_HDR.pack(fid, T_I64) + _I64.pack(value)
            else:
                out += _TLV_HDR.pack(fid, T_U64) + _U64.pack(value)
        elif isinstance(value, (bytes, bytearray)):
            out += _TLV_HDR.pack(fid, T_BYTES) + _U16.pack(len(value)) + bytes(value)
        elif isinstance(value, str):
            data = value.encode("utf-8")
            out += _TLV_HDR.pack(fid, T_BYTES) + _U16.pack(len(data)) + data
        elif isinstance(value, (list, tuple)) and all(
            isinstance(x, int) for x in value
        ):
            out += _TLV_HDR.pack(fid, T_I32_ARRAY) + _U16.pack(len(value))
            out += struct.pack(f"<{len(value)}i", *value)
        else:
            raise TypeError(f"cannot encode field {name!r}: {type(value).__name__}")

    return bytes(out)
