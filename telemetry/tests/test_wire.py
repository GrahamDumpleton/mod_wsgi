from mod_wsgi_telemetry.wire import (
    KIND_REQUEST,
    KIND_SLOW_REQUEST,
    Sample,
    decode,
    encode,
    FIELDS,
    FIELD_IDS,
)


def _roundtrip(fields):
    s = Sample(
        version=1,
        kind=KIND_REQUEST,
        pid=4242,
        seq=17,
        stamp_us=1_700_000_000_000_000,
        fields=fields,
    )
    blob = encode(s)
    got = decode(blob)
    assert got.kind == KIND_REQUEST
    assert got.pid == 4242
    assert got.seq == 17
    assert got.stamp_us == 1_700_000_000_000_000
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


def test_roundtrip_request_time_buckets():
    buckets = [1, 4, 9, 12, 5, 2, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    got = _roundtrip({"request_time_buckets": buckets})
    assert got.fields["request_time_buckets"] == buckets


def test_unknown_field_preserved_as_synthetic_name():
    # Emulate a newer emitter: reach past the known field ID map.
    fields = {f"id9999": 42}
    s = Sample(version=1, kind=KIND_REQUEST, pid=1, seq=1,
               stamp_us=0, fields=fields)
    blob = encode(s)
    got = decode(blob)
    assert got.fields["id9999"] == 42


def test_field_table_has_no_duplicate_ids():
    # Reverse map must be 1:1 with the forward map.
    assert len(FIELDS) == len(FIELD_IDS)


def test_roundtrip_slow_request():
    # Carries every slow_* field so any drift in the id table fails loud.
    fields = {
        "slow_state": 0,
        "slow_start_stamp_us": 1_700_000_000_000_000,
        "slow_duration_us": 1_234_000,
        "slow_thread_id": 3,
        "slow_log_id": b"abcd-1234",
        "slow_method": b"GET",
        "slow_scheme": b"https",
        "slow_hostname": b"web-01.internal",
        "slow_script_name": b"/app",
        "slow_path_info": b"/reports/render",
    }
    s = Sample(version=1, kind=KIND_SLOW_REQUEST, pid=5050, seq=3,
               stamp_us=1_700_000_000_000_000, fields=fields)
    got = decode(encode(s))
    assert got.kind == KIND_SLOW_REQUEST
    assert got.kind_name == "slow_request"
    assert got.fields["slow_state"] == 0
    assert got.fields["slow_duration_us"] == 1_234_000
    assert got.fields["slow_thread_id"] == 3
    assert got.fields["slow_log_id"] == b"abcd-1234"
    assert got.fields["slow_method"] == b"GET"
    assert got.fields["slow_scheme"] == b"https"
    assert got.fields["slow_hostname"] == b"web-01.internal"
    assert got.fields["slow_script_name"] == b"/app"
    assert got.fields["slow_path_info"] == b"/reports/render"


def test_roundtrip_slot_capacity_arrays():
    # All five per-slot capacity arrays must round-trip cleanly: reuse of
    # wire id 64 (now carrying slot_request_count) + the new 90-93 block.
    fields = {
        "slot_request_count":       [0, 3, 7, 0, 1],
        "slot_busy_time_us":        [0, 250_000, 980_000, 0, 120_000],
        "slot_cpu_time_us":         [0,  80_000, 200_000, 0,  40_000],
        "slot_current_elapsed_ms":  [0,       0,       0, 0,   2_500],
        "slot_max_duration_ms":     [0,      35,     142, 0,     280],
    }
    got = _roundtrip(fields)
    for name, expected in fields.items():
        assert got.fields[name] == expected, name


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
        "slow_state": 1,
        "slow_start_stamp_us": 1_700_000_000_000_000,
        "slow_duration_us": 8_000_000,
        "slow_thread_id": 7,
        "slow_input_bytes": 4096,
        "slow_input_reads": 1,
        "slow_output_bytes": 120 * 1024 * 1024,
        "slow_output_writes": 60_000,
    }
    s = Sample(version=1, kind=KIND_SLOW_REQUEST, pid=9090, seq=4,
               stamp_us=1_700_000_000_000_000, fields=fields)
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
        "slow_state": 1,
        "slow_duration_us": 5_000_000,
        "slow_thread_id": 2,
        "slow_cpu_user_us": 4_200_000,
        "slow_cpu_system_us": 300_000,
    }
    s = Sample(version=1, kind=KIND_SLOW_REQUEST, pid=7777, seq=5,
               stamp_us=1_700_000_000_000_000, fields=fields)
    got = decode(encode(s))
    assert got.fields["slow_cpu_user_us"] == 4_200_000
    assert got.fields["slow_cpu_system_us"] == 300_000


def test_rejects_bad_magic():
    s = Sample(version=1, kind=KIND_REQUEST, pid=1, seq=1,
               stamp_us=0, fields={"request_count": 1})
    blob = bytearray(encode(s))
    blob[0:4] = b"XXXX"
    import pytest
    with pytest.raises(Exception):
        decode(bytes(blob))
