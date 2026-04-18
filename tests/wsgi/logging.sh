# Test logging to sys.stdout, sys.stderr, and wsgi.errors.
#
# Sourced by scripts/run-tests.sh which provides:
#   BASE_URL, SERVER_ROOT, assert_status, assert_body_equals,
#   assert_log_contains, assert_log_not_contains

URL="$BASE_URL/test/wsgi/logging"

# Test sys.stdout logging.
assert_status "$URL/stdout" "200" \
    "stdout logging returns 200"

assert_body_equals "$URL/stdout" "stdout done" \
    "stdout logging returns expected body"

# Give the daemon process a moment to flush logs.
sleep 1

assert_log_contains "MARKER_STDOUT_TEST_12345" \
    "stdout message appears in error log"

# Test sys.stderr logging.
assert_status "$URL/stderr" "200" \
    "stderr logging returns 200"

sleep 1

assert_log_contains "MARKER_STDERR_TEST_12345" \
    "stderr message appears in error log"

# Test wsgi.errors logging.
assert_status "$URL/wsgi-errors" "200" \
    "wsgi.errors logging returns 200"

sleep 1

assert_log_contains "MARKER_WSGIERRORS_TEST_12345" \
    "wsgi.errors message appears in error log"

# Test all three streams in one request.
assert_status "$URL/all" "200" \
    "all streams logging returns 200"

sleep 1

assert_log_contains "MARKER_ALL_STDOUT_67890" \
    "stdout message from combined request in log"

assert_log_contains "MARKER_ALL_STDERR_67890" \
    "stderr message from combined request in log"

assert_log_contains "MARKER_ALL_WSGIERRORS_67890" \
    "wsgi.errors message from combined request in log"

# Test multi-line logging.
assert_status "$URL/multiline" "200" \
    "multiline logging returns 200"

sleep 1

assert_log_contains "MARKER_MULTI_LINE1_11111" \
    "first line of multiline message in log"

assert_log_contains "MARKER_MULTI_LINE2_11111" \
    "second line of multiline message in log"

# Test explicit flush.
assert_status "$URL/flush" "200" \
    "flush logging returns 200"

sleep 1

assert_log_contains "MARKER_FLUSH_TEST_22222" \
    "flushed message appears in error log"

# Test wsgi.errors.writelines().
assert_status "$URL/wsgi-errors-writelines" "200" \
    "wsgi.errors.writelines() returns 200"

sleep 1

assert_log_contains "MARKER_WRITELINES_A_33333" \
    "first line of writelines() appears in error log"

assert_log_contains "MARKER_WRITELINES_B_33333" \
    "second line of writelines() appears in error log"

assert_log_contains "MARKER_WRITELINES_C_33333" \
    "third line of writelines() appears in error log"
