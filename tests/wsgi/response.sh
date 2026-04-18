# Test WSGI response iteration behaviour in Adapter_run.
#
# Sourced by scripts/run-tests.sh which provides:
#   BASE_URL, assert_status, assert_body_equals,
#   assert_body_contains, assert_body_length, assert_log_contains

URL="$BASE_URL/test/wsgi/response"

# ----- Plain iterables -----

assert_body_equals "$URL/list" "chunk1-chunk2-chunk3" \
    "list response yields all items in order"

assert_body_equals "$URL/tuple" "tuple-atuple-b" \
    "tuple response yields all items in order"

# ----- Generator -----

assert_body_equals "$URL/generator" "gen-one-gen-two-gen-three" \
    "generator response yields all items"

# ----- Empty responses -----

assert_status "$URL/empty-list" "200" \
    "empty list response returns 200"

assert_body_length "$URL/empty-list" "0" \
    "empty list response has zero-length body"

assert_status "$URL/empty-generator" "200" \
    "empty generator response returns 200"

assert_body_length "$URL/empty-generator" "0" \
    "empty generator response has zero-length body"

# ----- close() called on custom iterable -----

assert_status "$URL/iterable-with-close" "200" \
    "custom iterable with close returns 200"

assert_body_equals "$URL/iterable-with-close" "iter-a-iter-b" \
    "custom iterable with close yields all items"

sleep 1
assert_log_contains "MARKER_ITER_CLOSE_77777" \
    "close() is called on the custom iterable after iteration finishes"

# ----- Generator try/finally runs on normal completion -----

assert_body_equals "$URL/generator-finally" "gen-fin-a-gen-fin-b" \
    "generator with try/finally yields all items"

sleep 1
assert_log_contains "MARKER_GEN_FINALLY_77777" \
    "generator finally block runs after normal iteration completes"

# ----- close() sends GeneratorExit into a paused generator -----

assert_status "$URL/close-via-generator-exit" "200" \
    "generator with bad item mid-stream still returns 200 after first chunk"

assert_body_equals "$URL/close-via-generator-exit" "first-ok" \
    "content before the bad item reaches the client"

sleep 1
assert_log_contains "MARKER_CLOSE_GEXIT_77777" \
    "finally runs when close() sends GeneratorExit into paused generator"

# ----- Exception before first yield -----

assert_status "$URL/raise-first" "500" \
    "app that raises before yielding returns 500"

# ----- Exception after first yield -----

assert_status "$URL/raise-midway" "200" \
    "app that raises after first chunk returns 200 (headers already sent)"

assert_body_equals "$URL/raise-midway" "before-boom" \
    "content sent before mid-stream exception reaches client"

# ----- Generator try/finally runs when raising after yield -----

assert_body_equals "$URL/raise-with-finally" "before-fin-err" \
    "pre-exception content reaches client before generator raise"

sleep 1
assert_log_contains "MARKER_RAISE_FINALLY_77777" \
    "finally block runs when generator raises after yielding"

# ----- Non-bytes items in iterable -----

assert_status "$URL/non-bytes-first" "500" \
    "iterable yielding str instead of bytes returns 500"

assert_status "$URL/non-bytes-midway" "200" \
    "iterable yielding non-bytes after first chunk returns 200"

assert_body_equals "$URL/non-bytes-midway" "bytes-ok" \
    "content sent before non-bytes item reaches client"

# ----- Content-Length enforcement -----

assert_body_length "$URL/content-length-exact" "10" \
    "exact Content-Length delivers all declared bytes"

assert_body_equals "$URL/content-length-exact" "exactly10!" \
    "exact Content-Length body matches declared content"

assert_body_length "$URL/content-length-over" "5" \
    "over-declared Content-Length truncates response to declared size"

assert_body_equals "$URL/content-length-over" "this-" \
    "over-declared Content-Length body is truncated at declared bytes"

# ----- Streaming many chunks -----

assert_status "$URL/many-chunks" "200" \
    "streaming many chunks returns 200"

assert_body_contains "$URL/many-chunks" "chunk000-" \
    "streamed body contains first chunk"

assert_body_contains "$URL/many-chunks" "chunk099-" \
    "streamed body contains last chunk"
