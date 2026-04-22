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


def test_rejects_bad_magic():
    s = Sample(version=1, kind=KIND_REQUEST, pid=1, seq=1,
               stamp_us=0, fields={"request_count": 1})
    blob = bytearray(encode(s))
    blob[0:4] = b"XXXX"
    import pytest
    with pytest.raises(Exception):
        decode(bytes(blob))
