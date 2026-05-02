# Test that a request routed to a named application group runs in a
# sub-interpreter (not the main interpreter of the daemon process).
# Routing is via tests/dispatch.py: requests under
# /test/wsgi/sub-interpreter are dispatched to application_group
# "test-subinterp", overriding the static "%{GLOBAL}" on the
# harness's WSGIScriptAlias. This exercises the Py_NewInterpreter
# branch in newInterpreterObject which no other test reaches.
#
# Sourced by scripts/run-tests.sh which provides:
#   BASE_URL, assert_body_equals

URL="$BASE_URL/test/wsgi/sub-interpreter"

assert_body_equals "$URL/application-group" \
    "application_group=test-subinterp;end" \
    "request runs in named sub-interpreter (not main)"
