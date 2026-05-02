# Test mod_wsgi metrics and event subscription system.
#
# Sourced by scripts/run-tests.sh which provides:
#   BASE_URL, SERVER_ROOT, assert_status, assert_body_contains,
#   assert_body_equals, assert_log_contains

URL="$BASE_URL/test/wsgi/metrics"

# -- Basic request works --

assert_status "$URL/basic" "200" \
    "basic metrics endpoint returns 200"

# -- Event subscription --
# After the basic request above, the events log should contain
# request lifecycle events from that request plus this one.

assert_status "$URL/events-log" "200" \
    "events log endpoint returns 200"

assert_body_contains "$URL/events-log" "request_started" \
    "events log contains request_started"

assert_body_contains "$URL/events-log" "response_started" \
    "events log contains response_started"

assert_body_contains "$URL/events-log" "request_finished" \
    "events log contains request_finished"

# -- request_finished event payload --
# The /request-finished-keys endpoint returns the union of keys seen
# across all request_finished events captured by the subscriber. Asserting
# specific keys ensures the new fields are being published.

assert_body_contains "$URL/request-finished-keys" "request_id" \
    "request_finished event contains request_id"

assert_body_contains "$URL/request-finished-keys" "thread_id" \
    "request_finished event contains thread_id"

assert_body_contains "$URL/request-finished-keys" "request_start" \
    "request_finished event contains request_start"

assert_body_contains "$URL/request-finished-keys" "queue_start" \
    "request_finished event contains queue_start"

assert_body_contains "$URL/request-finished-keys" "daemon_start" \
    "request_finished event contains daemon_start"

assert_body_contains "$URL/request-finished-keys" "status" \
    "request_finished event contains status"

assert_body_contains "$URL/request-finished-keys" "gil_wait_time" \
    "request_finished event contains gil_wait_time"

assert_body_contains "$URL/request-finished-keys" "gil_wait_count" \
    "request_finished event contains gil_wait_count"

# -- Request data --
# The event handler populates request_data with thread info.

assert_status "$URL/request-data" "200" \
    "request data endpoint returns 200"

assert_body_contains "$URL/request-data" "thread_name" \
    "request data contains thread_name from event handler"

assert_body_contains "$URL/request-data" "thread_id" \
    "request data contains thread_id from event handler"

assert_body_contains "$URL/request-data" "pid" \
    "request data contains pid from event handler"

# -- Process metrics --

assert_status "$URL/process-metrics" "200" \
    "process metrics endpoint returns 200"

assert_body_contains "$URL/process-metrics" "'pid'" \
    "process metrics contains pid"

assert_body_contains "$URL/process-metrics" "'request_count'" \
    "process metrics contains request_count"

assert_body_contains "$URL/process-metrics" "'request_busy_time'" \
    "process metrics contains request_busy_time"

assert_body_contains "$URL/process-metrics" "'threads'" \
    "process metrics contains threads"

# -- Request metrics --
# First call initialises the collection period (returns empty-ish dict).
# Second call returns actual metrics from the interval.

curl "${CURL_COMMON[@]}" -s "$URL/request-metrics" > /dev/null

# Generate some traffic between the two calls.
curl "${CURL_COMMON[@]}" -s "$URL/basic" > /dev/null
curl "${CURL_COMMON[@]}" -s "$URL/basic" > /dev/null
curl "${CURL_COMMON[@]}" -s "$URL/basic" > /dev/null

assert_status "$URL/request-metrics" "200" \
    "request metrics endpoint returns 200"

assert_body_contains "$URL/request-metrics" "'request_count'" \
    "request metrics contains request_count"

assert_body_contains "$URL/request-metrics" "'capacity_utilization'" \
    "request metrics contains capacity_utilization"

assert_body_contains "$URL/request-metrics" "'request_throughput'" \
    "request metrics contains request_throughput"

assert_body_contains "$URL/request-metrics" "'sample_period'" \
    "request metrics contains sample_period"

assert_body_contains "$URL/request-metrics" "'gil_wait_time'" \
    "request metrics contains gil_wait_time"

assert_body_contains "$URL/request-metrics" "'gil_wait_time_buckets'" \
    "request metrics contains gil_wait_time_buckets"

assert_body_contains "$URL/request-metrics" "'gil_wait_count'" \
    "request metrics contains gil_wait_count"

assert_body_contains "$URL/request-metrics" "'input_read_time'" \
    "request metrics contains input_read_time"

assert_body_contains "$URL/request-metrics" "'input_read_time_buckets'" \
    "request metrics contains input_read_time_buckets"

assert_body_contains "$URL/request-metrics" "'output_write_time'" \
    "request metrics contains output_write_time"

assert_body_contains "$URL/request-metrics" "'output_write_time_buckets'" \
    "request metrics contains output_write_time_buckets"

assert_body_contains "$URL/request-metrics" "'input_bytes'" \
    "request metrics contains input_bytes"

assert_body_contains "$URL/request-metrics" "'input_reads'" \
    "request metrics contains input_reads"

assert_body_contains "$URL/request-metrics" "'output_bytes'" \
    "request metrics contains output_bytes"

assert_body_contains "$URL/request-metrics" "'output_writes'" \
    "request metrics contains output_writes"

# -- Server metrics --
# May return None if server metrics not enabled. Just check it
# doesn't crash.

assert_status "$URL/server-metrics" "200" \
    "server metrics endpoint returns 200"
