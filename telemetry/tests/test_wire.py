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
        "slow_record_state": 0,
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
    assert got.fields["slow_record_state"] == 0
    assert got.fields["slow_duration_us"] == 1_234_000
    assert got.fields["slow_thread_id"] == 3
    assert got.fields["slow_log_id"] == b"abcd-1234"
    assert got.fields["slow_method"] == b"GET"
    assert got.fields["slow_scheme"] == b"https"
    assert got.fields["slow_hostname"] == b"web-01.internal"
    assert got.fields["slow_script_name"] == b"/app"
    assert got.fields["slow_path_info"] == b"/reports/render"


def test_roundtrip_slot_capacity_arrays():
    # All five per-slot capacity arrays must round-trip cleanly. Slot
    # arrays now live at 110-114 after the per-phase blocks were
    # widened to fit min/max alongside means and histograms.
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


def test_roundtrip_per_phase_means():
    # Per-phase means at 60-64. request_time (id 64) was added for
    # symmetry with the min/max/histogram blocks below — verify it
    # round-trips alongside the four pre-existing phase means.
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


def test_roundtrip_per_phase_min_max_us():
    # Per-phase exact min (70-74) and max (80-84) accumulators in
    # microseconds. Encoded by the C side only on ticks where at least
    # one request completed; absence == "no data this tick".
    fields = {
        "server_time_min_us":      1_500,
        "server_time_max_us":     12_000,
        "queue_time_min_us":         400,
        "queue_time_max_us":       3_200,
        "daemon_time_min_us":        300,
        "daemon_time_max_us":      1_900,
        "application_time_min_us": 8_000,
        "application_time_max_us": 95_000,
        "request_time_min_us":    11_000,
        "request_time_max_us":   118_000,
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
        "server_time_min_us",
        "application_time_min_us",
        "request_time_max_us",
    ):
        assert name not in got.fields


def test_roundtrip_hdr_request_time_buckets():
    # 65-entry HDR layout: 16 octaves × 4 sub-buckets + 1 overflow.
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
        "slow_record_state": 1,
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


def test_roundtrip_slow_request_phase_timings():
    # Per-phase timing breakdown. queue and daemon are 0 in embedded
    # mode; here we exercise daemon-mode values to prove all four
    # field IDs round-trip.
    fields = {
        "slow_record_state": 1,
        "slow_duration_us": 6_000_000,
        "slow_thread_id": 4,
        "slow_server_time_us": 50_000,
        "slow_queue_time_us": 200_000,
        "slow_daemon_time_us": 100_000,
        "slow_application_time_us": 5_650_000,
    }
    s = Sample(version=1, kind=KIND_SLOW_REQUEST, pid=8181, seq=11,
               stamp_us=1_700_000_000_000_000, fields=fields)
    got = decode(encode(s))
    assert got.fields["slow_server_time_us"] == 50_000
    assert got.fields["slow_queue_time_us"] == 200_000
    assert got.fields["slow_daemon_time_us"] == 100_000
    assert got.fields["slow_application_time_us"] == 5_650_000


def test_roundtrip_slow_request_client_identity():
    # peer_ip survives both IPv4 and IPv6 string forms; protocol is
    # the literal SERVER_PROTOCOL string; user_agent is the verbatim
    # request header (only emitted by the C side when
    # WSGIMetricsOptions +CaptureUserAgent, but the wire format
    # itself is symmetric and round-trips regardless).
    fields = {
        "slow_record_state": 1,
        "slow_duration_us": 2_000_000,
        "slow_thread_id": 1,
        "slow_peer_ip": b"203.0.113.42",
        "slow_protocol": b"HTTP/2.0",
        "slow_user_agent": b"Mozilla/5.0 (X11; Linux x86_64) curl/8.7.1",
    }
    s = Sample(version=1, kind=KIND_SLOW_REQUEST, pid=1234, seq=2,
               stamp_us=1_700_000_000_000_000, fields=fields)
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
                stamp_us=1_700_000_000_000_001, fields=fields6)
    got6 = decode(encode(s6))
    assert got6.fields["slow_peer_ip"] == b"2001:0db8:85a3:0000:0000:8a2e:0370:7334"


def test_roundtrip_slow_request_concurrency():
    # Concurrency context: in-flight count at slot claim and at
    # completion. active_at_completion is 0 for active records by
    # definition; here we exercise a completed record so both fields
    # carry non-zero values.
    fields = {
        "slow_record_state": 1,
        "slow_duration_us": 4_000_000,
        "slow_thread_id": 6,
        "slow_active_at_start": 12,
        "slow_active_at_completion": 9,
    }
    s = Sample(version=1, kind=KIND_SLOW_REQUEST, pid=9292, seq=13,
               stamp_us=1_700_000_000_000_000, fields=fields)
    got = decode(encode(s))
    assert got.fields["slow_active_at_start"] == 12
    assert got.fields["slow_active_at_completion"] == 9


def test_rejects_bad_magic():
    s = Sample(version=1, kind=KIND_REQUEST, pid=1, seq=1,
               stamp_us=0, fields={"request_count": 1})
    blob = bytearray(encode(s))
    blob[0:4] = b"XXXX"
    import pytest
    with pytest.raises(Exception):
        decode(bytes(blob))
