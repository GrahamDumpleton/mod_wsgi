# Tests for interrupt-timeout / RequestTimeout injection.
#
# Custom daemon group "interrupt-timeout-test" with request-timeout=2
# and interrupt-timeout=5 (see interrupt_timeout.conf). A request to
# /slow spins in pure Python; the monitor thread injects
# mod_wsgi.RequestTimeout, which unwinds to the adapter and produces
# a 504. The process must keep serving subsequent requests because
# injection succeeded — only the wedged thread was disturbed.

CATCH_MARKER="/tmp/mod_wsgi_interrupt_timeout_catch_marker"
rm -f "$CATCH_MARKER"

# Sanity check: process is healthy before we wedge anything.
assert_status "$BASE_URL/test/wsgi/interrupt-timeout/fast" 200 \
    "fast endpoint returns 200 before any injection"

# Wedged request is interrupted and returns 504.
assert_status "$BASE_URL/test/wsgi/interrupt-timeout/slow" 504 \
    "wedged request returns 504 after RequestTimeout injection"

# Process kept running: the fast endpoint still serves.
assert_status "$BASE_URL/test/wsgi/interrupt-timeout/fast" 200 \
    "fast endpoint still returns 200 after sibling thread was injected"

# User code that catches RequestTimeout and re-raises still gets 504.
assert_status "$BASE_URL/test/wsgi/interrupt-timeout/catch" 504 \
    "re-raised RequestTimeout still produces 504"

if [ -f "$CATCH_MARKER" ]; then
    echo "  PASS: user except RequestTimeout: branch ran before re-raise"
    PASS=$((PASS + 1))
else
    echo "  FAIL: user except RequestTimeout: branch did not run"
    FAIL=$((FAIL + 1))
    ERRORS="$ERRORS\n  FAIL: user except RequestTimeout: branch did not run"
fi
rm -f "$CATCH_MARKER"

# Process still healthy after both injections.
assert_status "$BASE_URL/test/wsgi/interrupt-timeout/fast" 200 \
    "fast endpoint still returns 200 after second injection"

# Error log carries the injection and recovery messages.
assert_log_contains "Injected RequestTimeout into thread" \
    "injection log line emitted"
assert_log_contains "Request interrupted by RequestTimeout; thread recovered" \
    "adapter recovery log line emitted"
