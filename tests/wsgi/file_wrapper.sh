# Test wsgi.file_wrapper with different scenarios.
#
# Sourced by scripts/run-tests.sh which provides:
#   BASE_URL, assert_status, assert_body_contains,
#   assert_body_equals, assert_body_length

URL="$BASE_URL/test/wsgi/file-wrapper"

assert_status "$URL/basic" "200" \
    "basic file wrapper returns 200"

assert_body_contains "$URL/basic" \
    "file_wrapper test: SUCCESS" \
    "basic file wrapper returns expected content"

assert_body_length "$URL/with-content-length" \
    "2700" \
    "file wrapper with content-length returns correct body size"

assert_status "$URL/partial" "200" \
    "partial file wrapper returns 200"

assert_body_length "$URL/partial" \
    "2673" \
    "partial file wrapper skipped first line"

assert_status "$URL/iterable-fallback" "200" \
    "iterable fallback returns 200"

assert_body_equals "$URL/iterable-fallback" \
    "file_wrapper iterable fallback: SUCCESS" \
    "iterable fallback returns expected content"
