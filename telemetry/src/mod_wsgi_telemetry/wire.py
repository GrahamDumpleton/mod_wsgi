"""TLV wire format decoder for mod_wsgi telemetry samples.

This file is the Python-side mirror of src/server/wsgi_telemetry.h on the
mod_wsgi C side. Field IDs and type tags must stay in sync. Once the C
header is committed, this table should be regenerated from it.

Wire layout:

  fixed header (24 bytes, little-endian):
    magic     uint32   b'WSGI'
    version   uint8
    kind      uint8    1=process, 2=request, 3=server, 4=slow_request,
                       5=process_started, 6=process_stopping, 7=process_stopped
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
KIND_PROCESS_STARTED = 5
KIND_PROCESS_STOPPING = 6
KIND_PROCESS_STOPPED = 7

KIND_NAMES = {
    KIND_PROCESS: "process_metrics",
    KIND_REQUEST: "request_metrics",
    KIND_SERVER: "server_metrics",
    KIND_SLOW_REQUEST: "slow_request",
    KIND_PROCESS_STARTED: "process_started",
    KIND_PROCESS_STOPPING: "process_stopping",
    KIND_PROCESS_STOPPED: "process_stopped",
}

# Type tags
T_U64 = 0x01
T_F64 = 0x02
T_I64 = 0x03
T_BYTES = 0x04
T_I32_ARRAY = 0x05

# Field ID table. Mirrors wsgi_telemetry.h. Grouped in blocks of 10 by
# concept; see the header for the authoritative groupings. IDs are kept
# stable while the wire format is in development; once a release is cut,
# they become append-only and renumbering is no longer permitted.
FIELDS = {
    # 1-9: identity. Build/runtime versions come first so a consumer
    # that wants to print a "who is this" banner can reach them without
    # scanning the whole TLV record. All seven fields are static for
    # the life of a process.
    1: "mod_wsgi_version",
    2: "python_version",
    3: "apache_version",
    4: "mpm_name",
    5: "hostname",
    6: "process_group",
    7: "process_parent_pid",

    # 10-19: sampling and reporter configuration. sample_period is the
    # measured wall-clock interval between snapshot calls (drifts with
    # scheduling jitter); telemetry_interval is the configured
    # WSGITelemetry directive (constant). slow_requests_threshold is
    # the configured WSGISlowRequests value in seconds (0 when the
    # directive is not configured).
    10: "sample_period",
    11: "telemetry_interval",
    12: "slow_requests_threshold",

    # 20-29: request rates and capacity for the interval.
    20: "request_count",
    21: "request_throughput",
    22: "capacity_utilization",

    # 30-39: CPU. *_utilization are interval rates from
    # wsgi_request_metrics; *_time are cumulative seconds reserved for
    # wsgi_process_metrics (not yet emitted on the wire).
    30: "cpu_user_utilization",
    31: "cpu_system_utilization",
    32: "cpu_utilization",
    35: "cpu_user_time",
    36: "cpu_system_time",
    37: "cpu_time",

    # 40-49: memory.
    40: "memory_rss",
    41: "memory_max_rss",

    # 50-59: worker-thread counts.
    50: "request_threads_maximum",
    51: "request_threads_started",
    52: "request_threads_active",

    # 60-69: per-phase mean times for the interval (seconds).
    # request_time is the per-request total
    # (server + queue + daemon + application) — what the caller actually
    # experienced. gil_wait_time, input_read_time and output_write_time
    # are cross-cutting overlap indicators that accumulate *during*
    # application_time and are *not* addends in the request_time
    # invariant. gil_wait_time is partial — see UI help text for the
    # full coverage caveat. output_write_time is adapter-handoff time
    # (Apache may buffer / async-flush past the WSGI app's return), not
    # client-receive latency.
    60: "server_time",
    61: "queue_time",
    62: "daemon_time",
    63: "application_time",
    64: "request_time",
    65: "gil_wait_time",
    66: "input_read_time",
    67: "output_write_time",

    # 70-79: per-phase exact min times for the interval (microseconds).
    # Only present on ticks where at least one request completed; the
    # encoder skips the field on idle ticks. Aggregate cleanly across
    # processes and across windows by min-of-mins — exact, no histogram
    # approximation.
    70: "server_time_min_us",
    71: "queue_time_min_us",
    72: "daemon_time_min_us",
    73: "application_time_min_us",
    74: "request_time_min_us",
    75: "gil_wait_time_min_us",
    76: "input_read_time_min_us",
    77: "output_write_time_min_us",

    # 80-89: per-phase exact max times for the interval (microseconds).
    # Same emission rule and aggregation semantics as the min block —
    # max-of-maxes is exact. Pairs with the histograms below to give a
    # true worst-case alongside bucket-bounded percentiles.
    80: "server_time_max_us",
    81: "queue_time_max_us",
    82: "daemon_time_max_us",
    83: "application_time_max_us",
    84: "request_time_max_us",
    85: "gil_wait_time_max_us",
    86: "input_read_time_max_us",
    87: "output_write_time_max_us",

    # 90-99: per-phase histograms. HDR-style: 16 octaves from 1 ms to
    # 65.5 s, each octave linearly split into 4 sub-buckets, plus one
    # overflow bucket for >65536 ms = 65 entries per phase. Max relative
    # error inside any sub-bucket is <=25%.
    90: "server_time_buckets",
    91: "queue_time_buckets",
    92: "daemon_time_buckets",
    93: "application_time_buckets",
    94: "request_time_buckets",
    95: "gil_wait_time_buckets",
    96: "input_read_time_buckets",
    97: "output_write_time_buckets",

    # 100-109: per-interval request I/O totals. Drained from the
    # adapter's InputObject.bytes/reads and
    # AdapterObject.output_length/output_writes at end-of-request;
    # in-flight requests don't contribute until they finish.
    100: "input_bytes_total",
    101: "input_reads_total",
    102: "output_bytes_total",
    103: "output_writes_total",

    # 110-119: per-slot capacity signals. One entry per worker thread,
    # carried as i32 arrays whose length matches the emitting process's
    # live request_threads_maximum.
    110: "slot_request_count",
    111: "slot_busy_time_us",
    112: "slot_cpu_time_us",
    113: "slot_current_elapsed_ms",
    114: "slot_max_duration_ms",

    # 120-129: per-interval HTTP response class totals. Drained from
    # the same accumulator that wsgi_record_request_times() updates at
    # end-of-request, sharing drain-and-reset semantics with the
    # 100-109 I/O totals block. status==0 (no start_response call) is
    # folded into status_5xx_total. 1xx is included as a PEP-3333
    # tripwire — a WSGI app should never return 1xx, so a non-zero
    # count flags a protocol violation. Sum equals request_count for
    # the same interval; consumers can use this as a sanity check.
    120: "status_1xx_total",
    121: "status_2xx_total",
    122: "status_3xx_total",
    123: "status_4xx_total",
    124: "status_5xx_total",

    # 130-139: lifecycle event payload. Only present in
    # KIND_PROCESS_STARTED, KIND_PROCESS_STOPPING and
    # KIND_PROCESS_STOPPED datagrams. Identity (hostname,
    # process_group) is repeated on each lifecycle datagram so it
    # stands alone — a STARTED can land before any periodic tick and
    # a STOPPED after the periodic stream has gone quiet, so neither
    # can rely on the KIND_PROCESS stream for context. The static
    # identity strings (versions, MPM, parent_pid) are only emitted on
    # STARTED — STOPPING and STOPPED expect the consumer to have keyed
    # them by pid.
    130: "shutdown_reason",
    131: "process_uptime",
    132: "lifetime_request_count",
    133: "active_requests_at_decision",
    134: "active_requests_at_exit",
    135: "graceful_drain",        # 0 = reaper aborted, 1 = drain completed cleanly

    # 160-199: reserved for future intermediate categories. Field IDs
    # are uint16 and the address space is effectively unbounded; this
    # gap exists so new conceptual blocks can be inserted before the
    # slow-request region without disturbing already-allocated IDs.

    # 200-299: slow-request fields (only present in KIND_SLOW_REQUEST
    # datagrams). Identity (hostname, process_group) is keyed per pid
    # from the accompanying KIND_REQUEST and KIND_PROCESS_STARTED
    # streams, so it is not repeated here. The 200-block reserves 100
    # IDs for the slow-record category so future additions land cleanly
    # within this range.
    #
    # Block layout:
    #   200-209: record metadata (state, start, duration, thread, log id)
    #   210-219: HTTP request identity (method, URL components, protocol,
    #            peer IP, user agent)
    #   220-229: per-phase timing breakdown (server / queue / daemon /
    #            application time, microseconds)
    #   230-239: per-request I/O counters
    #   240-249: response outcome (HTTP status; future error.type)
    #   250-259: per-request CPU and resource use
    #   260-269: concurrency context (in-flight counts at boundaries)
    #   270-289: reserved for future trace-context fields
    #   290-299: reserved
    #
    # Active records carry zero for fields not yet observable.
    200: "slow_record_state",     # 0 = active, 1 = completed
    201: "slow_start_stamp_us",
    202: "slow_duration_us",
    203: "slow_thread_id",
    204: "slow_log_id",

    210: "slow_method",
    211: "slow_scheme",
    212: "slow_hostname",
    213: "slow_script_name",
    214: "slow_path_info",
    215: "slow_protocol",              # "HTTP/1.1", "HTTP/2.0"
    216: "slow_peer_ip",                # post-trusted-proxy resolution
    217: "slow_user_agent",             # only when WSGIMetricsOptions +CaptureUserAgent

    220: "slow_server_time_us",
    221: "slow_queue_time_us",         # 0 in embedded mode
    222: "slow_daemon_time_us",        # 0 in embedded mode
    223: "slow_application_time_us",   # partial for active records still in flight
    224: "slow_gil_wait_us",            # GIL-wait pressure indicator; running total for active records
    225: "slow_gil_wait_count",         # number of re-acquire events observed

    230: "slow_input_bytes",
    231: "slow_input_reads",
    232: "slow_output_bytes",
    233: "slow_output_writes",
    234: "slow_input_read_us",     # per-request total time inside wsgi.input.read*
    235: "slow_output_write_us",   # per-request total time inside adapter output path

    240: "slow_status",           # 0 = not yet known, else final WSGI status

    250: "slow_cpu_user_us",
    251: "slow_cpu_system_us",

    260: "slow_active_at_start",        # in-flight count including this request
    261: "slow_active_at_completion",   # 0 for active records
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
