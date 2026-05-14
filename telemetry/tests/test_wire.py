from mod_wsgi_telemetry.wire import (
    KIND_REQUEST,
    KIND_SLOW_REQUEST,
    Sample,
    decode,
    encode,
    FIELDS,
    FIELD_IDS,
)


_STAMP = 1_700_000_000.123456


def _roundtrip(fields):
    s = Sample(
        version=1,
        kind=KIND_REQUEST,
        pid=4242,
        seq=17,
        stamp=_STAMP,
        fields=fields,
    )
    blob = encode(s)
    got = decode(blob)
    assert got.kind == KIND_REQUEST
    assert got.pid == 4242
    assert got.seq == 17
    assert got.stamp == _STAMP
    return got


def test_roundtrip_primitives():
    got = _roundtrip({
        "sample_period": 1.5,
        "request_count": 123,
        "request_throughput": 97.25,
        "capacity_utilization": 0.42,
    })
    assert got.fields["request_count"] == 123
    assert got.fields["request_throughput"] == 97.25


def test_roundtrip_bytes():
    got = _roundtrip({"hostname": "example.local", "process_group": b"grpA"})
    assert got.fields["hostname"] == b"example.local"
    assert got.fields["process_group"] == b"grpA"


def test_roundtrip_i32_array():
    buckets = [0, 5, 12, 8, 3, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    got = _roundtrip({"application_time_buckets": buckets})
    assert got.fields["application_time_buckets"] == buckets


def test_roundtrip_f64_array():
    # New T_F64_ARRAY type, used for the per-worker-slot time arrays.
    busy = [0.0, 0.25, 0.98, 0.0, 0.12]
    got = _roundtrip({"request_threads_busy_time": busy})
    assert got.fields["request_threads_busy_time"] == busy


def test_roundtrip_request_time_buckets():
    buckets = [1, 4, 9, 12, 5, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    got = _roundtrip({"request_time_buckets": buckets})
    assert got.fields["request_time_buckets"] == buckets


def test_unknown_field_preserved_as_synthetic_name():
    # Emulate a newer emitter: reach past the known field ID map.
    fields = {f"id9999": 42}
    s = Sample(version=1, kind=KIND_REQUEST, pid=1, seq=1,
               stamp=0.0, fields=fields)
    blob = encode(s)
    got = decode(blob)
    assert got.fields["id9999"] == 42


def test_field_table_has_no_duplicate_ids():
    # Reverse map must be 1:1 with the forward map.
    assert len(FIELDS) == len(FIELD_IDS)


def test_header_stamp_is_float_seconds():
    # Header stamp is f64 seconds since the Unix epoch; verify a value
    # with sub-second precision round-trips bit-for-bit.
    s = Sample(version=1, kind=KIND_REQUEST, pid=1, seq=1,
               stamp=1_700_000_000.654321, fields={"request_count": 1})
    got = decode(encode(s))
    assert got.stamp == 1_700_000_000.654321


def test_roundtrip_slow_request():
    # Carries every slow_* field so any drift in the id table fails loud.
    fields = {
        "slow_record_state": 0,
        "slow_start_stamp": 1_700_000_000.123,
        "slow_duration": 1.234,
        "slow_thread_id": 3,
        "slow_log_id": b"abcd-1234",
        "slow_method": b"GET",
        "slow_scheme": b"https",
        "slow_hostname": b"web-01.internal",
        "slow_script_name": b"/app",
        "slow_path_info": b"/reports/render",
    }
    s = Sample(version=1, kind=KIND_SLOW_REQUEST, pid=5050, seq=3,
               stamp=_STAMP, fields=fields)
    got = decode(encode(s))
    assert got.kind == KIND_SLOW_REQUEST
    assert got.kind_name == "slow_request"
    assert got.fields["slow_record_state"] == 0
    assert got.fields["slow_duration"] == 1.234
    assert got.fields["slow_thread_id"] == 3
    assert got.fields["slow_log_id"] == b"abcd-1234"
    assert got.fields["slow_method"] == b"GET"
    assert got.fields["slow_scheme"] == b"https"
    assert got.fields["slow_hostname"] == b"web-01.internal"
    assert got.fields["slow_script_name"] == b"/app"
    assert got.fields["slow_path_info"] == b"/reports/render"


def test_roundtrip_per_worker_slot_arrays():
    # Per-worker-slot capacity arrays at 110-114. Field names parallel
    # the same-shape keys in the request_metrics() Python dict; the
    # four time-valued arrays are f64 seconds, the completed-count
    # array stays an i32 count array.
    fields = {
        "request_threads_completed":       [0, 3, 7, 0, 1],
        "request_threads_busy_time":       [0.0, 0.25, 0.98, 0.0, 0.12],
        "request_threads_cpu_time":        [0.0, 0.08, 0.20, 0.0, 0.04],
        "request_threads_current_elapsed": [0.0, 0.0,  0.0,  0.0, 2.5],
        "request_threads_max_duration":    [0.0, 0.035, 0.142, 0.0, 0.28],
    }
    got = _roundtrip(fields)
    for name, expected in fields.items():
        assert got.fields[name] == expected, name


def test_roundtrip_per_phase_means():
    # Per-phase means at 60-67. All are f64 seconds.
    fields = {
        "server_time": 0.0042,
        "queue_time": 0.0011,
        "daemon_time": 0.0008,
        "application_time": 0.0240,
        "request_time": 0.0301,
    }
    got = _roundtrip(fields)
    for name, expected in fields.items():
        assert got.fields[name] == expected, name


def test_roundtrip_per_phase_min_max():
    # Per-phase exact min (70-77) and max (80-87) accumulators in
    # seconds. Encoded by the C side only on ticks where at least one
    # request completed; absence == "no data this tick".
    fields = {
        "server_time_min":      0.0015,
        "server_time_max":      0.012,
        "queue_time_min":       0.0004,
        "queue_time_max":       0.0032,
        "daemon_time_min":      0.0003,
        "daemon_time_max":      0.0019,
        "application_time_min": 0.008,
        "application_time_max": 0.095,
        "request_time_min":     0.011,
        "request_time_max":     0.118,
    }
    got = _roundtrip(fields)
    for name, expected in fields.items():
        assert got.fields[name] == expected, name


def test_per_phase_min_max_absent_on_idle_tick():
    # The C encoder skips the min/max fields when no requests
    # completed in the tick. The decoder must not invent them.
    got = _roundtrip({
        "server_time": 0.0,
        "request_count": 0,
    })
    for name in (
        "server_time_min",
        "application_time_min",
        "request_time_max",
    ):
        assert name not in got.fields


def test_roundtrip_hdr_request_time_buckets():
    # 65-entry HDR layout: 16 octaves x 4 sub-buckets + 1 overflow.
    # Spot-check that the wire format carries the full array intact.
    buckets = [0] * 65
    buckets[0] = 7        # [1, 1.25) ms
    buckets[12] = 312     # [8, 10) ms
    buckets[20] = 91      # [32, 40) ms
    buckets[40] = 5       # [1024, 1280) ms
    buckets[64] = 1       # >65536 ms (overflow)
    got = _roundtrip({"request_time_buckets": buckets})
    assert len(got.fields["request_time_buckets"]) == 65
    assert got.fields["request_time_buckets"] == buckets


def test_roundtrip_reporter_config():
    # Telemetry reporter and slow-request configuration fields, used
    # by the UI to explain matcher misses and clamp the heatmap
    # stuck-threshold dropdown.
    fields = {
        "telemetry_interval": 1.5,
        "slow_requests_threshold": 2.0,
    }
    got = _roundtrip(fields)
    assert got.fields["telemetry_interval"] == 1.5
    assert got.fields["slow_requests_threshold"] == 2.0


def test_roundtrip_request_io_totals():
    # Aggregate request I/O fields drained by wsgi_metrics_snapshot.
    fields = {
        "input_bytes_total": 12_345_678,
        "input_reads_total": 4321,
        "output_bytes_total": 987_654_321,
        "output_writes_total": 56_789,
    }
    got = _roundtrip(fields)
    for name, expected in fields.items():
        assert got.fields[name] == expected, name


def test_roundtrip_slow_request_io():
    # Per-slow-request I/O fields populated from the slot at end-of-request
    # (final, completed) or scanned from the still-live adapter (partial,
    # active). Both share the same wire IDs.
    fields = {
        "slow_record_state": 1,
        "slow_start_stamp": 1_700_000_000.0,
        "slow_duration": 8.0,
        "slow_thread_id": 7,
        "slow_input_bytes": 4096,
        "slow_input_reads": 1,
        "slow_output_bytes": 120 * 1024 * 1024,
        "slow_output_writes": 60_000,
    }
    s = Sample(version=1, kind=KIND_SLOW_REQUEST, pid=9090, seq=4,
               stamp=_STAMP, fields=fields)
    got = decode(encode(s))
    assert got.fields["slow_input_bytes"] == 4096
    assert got.fields["slow_input_reads"] == 1
    assert got.fields["slow_output_bytes"] == 120 * 1024 * 1024
    assert got.fields["slow_output_writes"] == 60_000


def test_roundtrip_slow_request_cpu():
    # Per-slow-request CPU time, broken out user/system so the UI's
    # drill-down can show both. Active records carry zero on the wire
    # (getrusage on a worker thread can only run from that worker).
    fields = {
        "slow_record_state": 1,
        "slow_duration": 5.0,
        "slow_thread_id": 2,
        "slow_cpu_user_time": 4.2,
        "slow_cpu_system_time": 0.3,
    }
    s = Sample(version=1, kind=KIND_SLOW_REQUEST, pid=7777, seq=5,
               stamp=_STAMP, fields=fields)
    got = decode(encode(s))
    assert got.fields["slow_cpu_user_time"] == 4.2
    assert got.fields["slow_cpu_system_time"] == 0.3


def test_roundtrip_slow_request_phase_timings():
    # Per-phase timing breakdown. queue and daemon are 0 in embedded
    # mode; here we exercise daemon-mode values to prove all four
    # field IDs round-trip.
    fields = {
        "slow_record_state": 1,
        "slow_duration": 6.0,
        "slow_thread_id": 4,
        "slow_server_time": 0.05,
        "slow_queue_time": 0.2,
        "slow_daemon_time": 0.1,
        "slow_application_time": 5.65,
    }
    s = Sample(version=1, kind=KIND_SLOW_REQUEST, pid=8181, seq=11,
               stamp=_STAMP, fields=fields)
    got = decode(encode(s))
    assert got.fields["slow_server_time"] == 0.05
    assert got.fields["slow_queue_time"] == 0.2
    assert got.fields["slow_daemon_time"] == 0.1
    assert got.fields["slow_application_time"] == 5.65


def test_roundtrip_slow_request_client_identity():
    # peer_ip survives both IPv4 and IPv6 string forms; protocol is
    # the literal SERVER_PROTOCOL string; user_agent is the verbatim
    # request header (only emitted by the C side when
    # WSGITelemetryOptions +CaptureUserAgent, but the wire format
    # itself is symmetric and round-trips regardless).
    fields = {
        "slow_record_state": 1,
        "slow_duration": 2.0,
        "slow_thread_id": 1,
        "slow_peer_ip": b"203.0.113.42",
        "slow_protocol": b"HTTP/2.0",
        "slow_user_agent": b"Mozilla/5.0 (X11; Linux x86_64) curl/8.7.1",
    }
    s = Sample(version=1, kind=KIND_SLOW_REQUEST, pid=1234, seq=2,
               stamp=_STAMP, fields=fields)
    got = decode(encode(s))
    assert got.fields["slow_peer_ip"] == b"203.0.113.42"
    assert got.fields["slow_protocol"] == b"HTTP/2.0"
    assert got.fields["slow_user_agent"] == \
        b"Mozilla/5.0 (X11; Linux x86_64) curl/8.7.1"

    # IPv6 case (longest plausible address still fits in 46 bytes).
    fields6 = {
        "slow_record_state": 1,
        "slow_peer_ip": b"2001:0db8:85a3:0000:0000:8a2e:0370:7334",
        "slow_protocol": b"HTTP/1.1",
    }
    s6 = Sample(version=1, kind=KIND_SLOW_REQUEST, pid=1235, seq=3,
                stamp=_STAMP + 0.000001, fields=fields6)
    got6 = decode(encode(s6))
    assert got6.fields["slow_peer_ip"] == b"2001:0db8:85a3:0000:0000:8a2e:0370:7334"


def test_roundtrip_slow_request_concurrency():
    # Concurrency context: in-flight count at slot claim and at
    # completion. active_at_completion is 0 for active records by
    # definition; here we exercise a completed record so both fields
    # carry non-zero values.
    fields = {
        "slow_record_state": 1,
        "slow_duration": 4.0,
        "slow_thread_id": 6,
        "slow_active_at_start": 12,
        "slow_active_at_completion": 9,
    }
    s = Sample(version=1, kind=KIND_SLOW_REQUEST, pid=9292, seq=13,
               stamp=_STAMP, fields=fields)
    got = decode(encode(s))
    assert got.fields["slow_active_at_start"] == 12
    assert got.fields["slow_active_at_completion"] == 9


def test_rejects_bad_magic():
    s = Sample(version=1, kind=KIND_REQUEST, pid=1, seq=1,
               stamp=0.0, fields={"request_count": 1})
    blob = bytearray(encode(s))
    blob[0:4] = b"XXXX"
    import pytest
    with pytest.raises(Exception):
        decode(bytes(blob))
