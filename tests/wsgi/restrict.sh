# Test mod_wsgi.Restricted objects on sys.stdin.
#
# Server is configured with WSGIRestrictStdin On.
#
# Sourced by scripts/run-tests.sh which provides:
#   BASE_URL, SERVER_ROOT, assert_status, assert_body_equals,
#   assert_body_contains

URL="$BASE_URL/test/wsgi/restrict"

# sys.stdin should be a Restricted object.
assert_status "$URL/stdin-type" "200" \
    "stdin type check returns 200"

assert_body_equals "$URL/stdin-type" "mod_wsgi.Restricted" \
    "sys.stdin is mod_wsgi.Restricted"

# Accessing any attribute on restricted stdin should raise OSError.
assert_status "$URL/stdin-read" "200" \
    "stdin read attempt returns 200"

assert_body_contains "$URL/stdin-read" "RESTRICTED:" \
    "accessing sys.stdin.read raises OSError"

assert_body_contains "$URL/stdin-read" "sys.stdin" \
    "OSError message mentions sys.stdin"

# sys.stderr should never be restricted.
assert_status "$URL/stderr-type" "200" \
    "stderr type check returns 200"

assert_body_contains "$URL/stderr-type" "TextIOWrapper" \
    "sys.stderr is not restricted (is a TextIOWrapper)"
