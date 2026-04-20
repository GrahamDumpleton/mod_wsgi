#!/bin/bash

# Run integration tests for mod_wsgi.
#
# Usage:
#   ./scripts/run-tests.sh                          # run all tests
#   ./scripts/run-tests.sh tests/wsgi/file_wrapper  # run specific test

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
SERVER_ROOT="$PROJECT_DIR/httpd-tests"
PORT=9876
HTTPS_PORT=9877
# The harness configures the test httpd with --server-name
# example.com so requests always address a stable name-based
# VirtualHost rather than relying on name-based matching of
# "localhost", which collides with the auto-generated _default_
# VirtualHost mod_wsgi-express emits alongside it. curl is pointed
# at example.com but --resolve below pins the address to 127.0.0.1.
SERVER_NAME=example.com
BASE_URL="http://$SERVER_NAME:$PORT"
HTTPS_BASE_URL="https://$SERVER_NAME:$HTTPS_PORT"

# Common flags prepended to every curl invocation in the helpers:
# -k disables cert verification against the throwaway self-signed
# HTTPS cert, and --resolve maps the test hostname to loopback for
# both listeners so no DNS or /etc/hosts changes are needed.
CURL_COMMON=(
    -k
    --resolve "$SERVER_NAME:$PORT:127.0.0.1"
    --resolve "$SERVER_NAME:$HTTPS_PORT:127.0.0.1"
)

PASS=0
FAIL=0
ERRORS=""

# ---- Pre-flight cleanup ----

# Stop any leftover server from a previous run.
if [ -f "$SERVER_ROOT/apachectl" ]; then
    "$SERVER_ROOT/apachectl" stop 2>/dev/null || true
fi

# Wait for the HTTP and HTTPS ports to be free (httpd may take several
# seconds to shut down cleanly).
for p in "$PORT" "$HTTPS_PORT"; do
    tries=0
    while lsof -i :"$p" -t >/dev/null 2>&1; do
        tries=$((tries + 1))
        if [ $tries -gt 10 ]; then
            # Force kill anything still holding the port.
            lsof -i :"$p" -t 2>/dev/null | xargs kill -9 2>/dev/null || true
            sleep 1
            break
        fi
        sleep 1
    done
done

# ---- Assertion helpers (available to test .sh files) ----

assert_status() {
    local url="$1"
    local expected_status="$2"
    local description="$3"

    local status
    status=$(curl "${CURL_COMMON[@]}" -s -o /dev/null -w '%{http_code}' "$url")

    if [ "$status" = "$expected_status" ]; then
        echo "  PASS: $description"
        PASS=$((PASS + 1))
    else
        echo "  FAIL: $description (expected status $expected_status, got $status)"
        FAIL=$((FAIL + 1))
        ERRORS="$ERRORS\n  FAIL: $description"
    fi
}

assert_body_contains() {
    local url="$1"
    local expected="$2"
    local description="$3"

    local body
    body=$(curl "${CURL_COMMON[@]}" -s "$url")

    if echo "$body" | grep -qF "$expected"; then
        echo "  PASS: $description"
        PASS=$((PASS + 1))
    else
        echo "  FAIL: $description (body does not contain '$expected')"
        FAIL=$((FAIL + 1))
        ERRORS="$ERRORS\n  FAIL: $description"
    fi
}

assert_body_equals() {
    local url="$1"
    local expected="$2"
    local description="$3"

    local body
    body=$(curl "${CURL_COMMON[@]}" -s "$url")

    if [ "$body" = "$expected" ]; then
        echo "  PASS: $description"
        PASS=$((PASS + 1))
    else
        echo "  FAIL: $description (body mismatch)"
        FAIL=$((FAIL + 1))
        ERRORS="$ERRORS\n  FAIL: $description"
    fi
}

assert_body_length() {
    local url="$1"
    local expected_length="$2"
    local description="$3"

    local actual_length
    actual_length=$(curl "${CURL_COMMON[@]}" -s "$url" | wc -c | tr -d ' ')

    if [ "$actual_length" = "$expected_length" ]; then
        echo "  PASS: $description"
        PASS=$((PASS + 1))
    else
        echo "  FAIL: $description (expected length $expected_length, got $actual_length)"
        FAIL=$((FAIL + 1))
        ERRORS="$ERRORS\n  FAIL: $description"
    fi
}

assert_log_contains() {
    local expected="$1"
    local description="$2"

    if grep -qF "$expected" "$SERVER_ROOT/error_log"; then
        echo "  PASS: $description"
        PASS=$((PASS + 1))
    else
        echo "  FAIL: $description (log does not contain '$expected')"
        FAIL=$((FAIL + 1))
        ERRORS="$ERRORS\n  FAIL: $description"
    fi
}

assert_log_not_contains() {
    local unexpected="$1"
    local description="$2"

    if grep -qF "$unexpected" "$SERVER_ROOT/error_log"; then
        echo "  FAIL: $description (log contains '$unexpected')"
        FAIL=$((FAIL + 1))
        ERRORS="$ERRORS\n  FAIL: $description"
    else
        echo "  PASS: $description"
        PASS=$((PASS + 1))
    fi
}

assert_post_body_equals() {
    local url="$1"
    local post_data="$2"
    local expected="$3"
    local description="$4"

    local body
    body=$(printf '%s' "$post_data" | curl "${CURL_COMMON[@]}" -s -X POST --data-binary @- "$url")

    if [ "$body" = "$expected" ]; then
        echo "  PASS: $description"
        PASS=$((PASS + 1))
    else
        echo "  FAIL: $description (body mismatch)"
        FAIL=$((FAIL + 1))
        ERRORS="$ERRORS\n  FAIL: $description"
    fi
}

assert_header_equals() {
    local url="$1"
    local header_name="$2"
    local expected_value="$3"
    local description="$4"

    local actual
    actual=$(curl "${CURL_COMMON[@]}" -sD - -o /dev/null "$url" \
        | grep -i "^${header_name}:" \
        | head -1 \
        | sed "s/^[^:]*: *//" \
        | tr -d '\r')

    if [ "$actual" = "$expected_value" ]; then
        echo "  PASS: $description"
        PASS=$((PASS + 1))
    else
        echo "  FAIL: $description (expected '$expected_value', got '$actual')"
        FAIL=$((FAIL + 1))
        ERRORS="$ERRORS\n  FAIL: $description"
    fi
}

assert_body_equals_headers() {
    local url="$1"
    local expected="$2"
    local description="$3"
    shift 3

    local body
    body=$(curl "${CURL_COMMON[@]}" -s "$@" "$url")

    if [ "$body" = "$expected" ]; then
        echo "  PASS: $description"
        PASS=$((PASS + 1))
    else
        echo "  FAIL: $description (expected '$expected', got '$body')"
        FAIL=$((FAIL + 1))
        ERRORS="$ERRORS\n  FAIL: $description"
    fi
}

assert_body_contains_headers() {
    local url="$1"
    local expected="$2"
    local description="$3"
    shift 3

    local body
    body=$(curl "${CURL_COMMON[@]}" -s "$@" "$url")

    if echo "$body" | grep -qF "$expected"; then
        echo "  PASS: $description"
        PASS=$((PASS + 1))
    else
        echo "  FAIL: $description (body does not contain '$expected')"
        FAIL=$((FAIL + 1))
        ERRORS="$ERRORS\n  FAIL: $description"
    fi
}

# Like assert_header_equals but with arbitrary extra curl args
# (e.g., -X HEAD, -H 'Some: header') passed after the description.
assert_header_equals_curl() {
    local url="$1"
    local header_name="$2"
    local expected_value="$3"
    local description="$4"
    shift 4

    local actual
    actual=$(curl "${CURL_COMMON[@]}" -sD - -o /dev/null "$@" "$url" \
        | grep -i "^${header_name}:" \
        | head -1 \
        | sed "s/^[^:]*: *//" \
        | tr -d '\r')

    if [ "$actual" = "$expected_value" ]; then
        echo "  PASS: $description"
        PASS=$((PASS + 1))
    else
        echo "  FAIL: $description (expected '$expected_value', got '$actual')"
        FAIL=$((FAIL + 1))
        ERRORS="$ERRORS\n  FAIL: $description"
    fi
}

# Like assert_status but with arbitrary extra curl args
# (e.g., -u user:pass, --digest).
assert_status_curl() {
    local url="$1"
    local expected_status="$2"
    local description="$3"
    shift 3

    local status
    status=$(curl "${CURL_COMMON[@]}" -s -o /dev/null -w '%{http_code}' "$@" "$url")

    if [ "$status" = "$expected_status" ]; then
        echo "  PASS: $description"
        PASS=$((PASS + 1))
    else
        echo "  FAIL: $description (expected status $expected_status, got $status)"
        FAIL=$((FAIL + 1))
        ERRORS="$ERRORS\n  FAIL: $description"
    fi
}

# POST body equality with extra curl args (e.g., for
# Transfer-Encoding: chunked or non-default Content-Type).
assert_post_body_equals_curl() {
    local url="$1"
    local post_data="$2"
    local expected="$3"
    local description="$4"
    shift 4

    local body
    body=$(printf '%s' "$post_data" \
        | curl "${CURL_COMMON[@]}" -s -X POST --data-binary @- "$@" "$url")

    if [ "$body" = "$expected" ]; then
        echo "  PASS: $description"
        PASS=$((PASS + 1))
    else
        echo "  FAIL: $description (expected '$expected', got '$body')"
        FAIL=$((FAIL + 1))
        ERRORS="$ERRORS\n  FAIL: $description"
    fi
}

assert_header_count() {
    local url="$1"
    local header_name="$2"
    local expected_count="$3"
    local description="$4"

    # grep -c exits 1 when there are no matches which would trip
    # `set -e` before we could compare the count, so swallow the
    # exit code with `|| true` and rely on grep's printed "0".
    local actual
    actual=$(curl "${CURL_COMMON[@]}" -sD - -o /dev/null "$url" \
        | grep -ic "^${header_name}:" || true)

    if [ "$actual" = "$expected_count" ]; then
        echo "  PASS: $description"
        PASS=$((PASS + 1))
    else
        echo "  FAIL: $description (expected $expected_count, got $actual)"
        FAIL=$((FAIL + 1))
        ERRORS="$ERRORS\n  FAIL: $description"
    fi
}

# ---- Server management ----

start_server() {
    local include_file="$1"

    rm -rf "$SERVER_ROOT"

    # --server-name activates MOD_WSGI_VIRTUAL_HOST mode in the
    # generated Apache config, which is required for the SSL
    # VirtualHost block that enables HTTPS on --https-port.
    # --ssl-environment turns on SSLOptions +StdEnvVars so mod_ssl
    # populates HTTPS=on and SSL_* entries in subprocess_env.
    # example.com is used as the server name rather than localhost
    # because the latter clashes with Apache's default ServerName
    # inheritance and lets the _default_ VirtualHost shadow
    # server-scope <Location> directives (e.g. authnz auth config).
    local setup_args=(
        tests/hello.wsgi
        --server-root "$SERVER_ROOT"
        --port "$PORT"
        --server-name "$SERVER_NAME"
        --https-port "$HTTPS_PORT"
        --ssl-certificate-file "$CERT_DIR/test.crt"
        --ssl-certificate-key-file "$CERT_DIR/test.key"
        --ssl-environment
        --log-level info
    )

    if [ -n "$include_file" ]; then
        setup_args+=(--include-file "$include_file")
    fi

    .venv/bin/mod_wsgi-express setup-server "${setup_args[@]}"

    "$SERVER_ROOT/apachectl" start

    local tries=0
    while [ ! -f "$SERVER_ROOT/httpd.pid" ]; do
        tries=$((tries + 1))
        if [ $tries -gt 15 ]; then
            echo "ERROR: Server did not start"
            cat "$SERVER_ROOT/error_log" 2>/dev/null
            exit 1
        fi
        sleep 1
    done

    sleep 1
}

stop_server() {
    if [ -f "$SERVER_ROOT/apachectl" ]; then
        "$SERVER_ROOT/apachectl" stop 2>/dev/null || true
    fi

    # Wait for clean shutdown of both listeners, then force kill if
    # needed.
    for p in "$PORT" "$HTTPS_PORT"; do
        local tries=0
        while lsof -i :"$p" -t >/dev/null 2>&1; do
            tries=$((tries + 1))
            if [ $tries -gt 10 ]; then
                lsof -i :"$p" -t 2>/dev/null | xargs kill -9 2>/dev/null || true
                sleep 1
                break
            fi
            sleep 1
        done
    done

    rm -rf "$SERVER_ROOT"
}

# ---- Discover and run tests ----

cd "$PROJECT_DIR"

# Find test .sh files, optionally filtered by argument.
if [ $# -gt 0 ]; then
    # Allow specifying without extension, e.g., tests/wsgi/file_wrapper
    TEST_FILES=()
    for arg in "$@"; do
        arg="${arg%.sh}"
        if [ -f "${arg}.sh" ]; then
            TEST_FILES+=("${arg}.sh")
        else
            echo "ERROR: Test not found: ${arg}.sh"
            exit 1
        fi
    done
else
    TEST_FILES=($(find tests -name '*.sh' -type f | sort))
fi

if [ ${#TEST_FILES[@]} -eq 0 ]; then
    echo "No test files found."
    exit 0
fi

# Generate a throwaway self-signed certificate for the HTTPS
# listener. Kept outside $SERVER_ROOT because start_server() wipes
# that directory on each run.
CERT_DIR=$(mktemp -d)
openssl req -x509 -nodes -newkey rsa:2048 \
    -keyout "$CERT_DIR/test.key" \
    -out    "$CERT_DIR/test.crt" \
    -days 1 \
    -subj "/CN=$SERVER_NAME" 2>/dev/null

# Build Apache include file mounting each test app.
INCLUDE_FILE=$(mktemp)
trap "rm -f $INCLUDE_FILE; rm -rf $CERT_DIR; stop_server" EXIT

# Grant Apache access to the tests directory and configure
# server-level directives for testing. MOD_WSGI_TESTS_DAEMON_PORT
# is read by tests/dispatch.py so that HTTPS requests (whose
# SERVER_PORT is $HTTPS_PORT) still route to the single daemon
# process group bound to $PORT.
cat >> "$INCLUDE_FILE" <<EOF
Define TESTS_DIR $PROJECT_DIR/tests
<Directory $PROJECT_DIR/tests>
    Require all granted
</Directory>
SetEnv MOD_WSGI_TESTS_DAEMON_PORT $PORT
WSGIRestrictStdin On
WSGIDispatchScript $PROJECT_DIR/tests/dispatch.py
EOF

for test_sh in "${TEST_FILES[@]}"; do
    test_py="${test_sh%.sh}.py"
    if [ ! -f "$test_py" ]; then
        echo "WARNING: No matching .py for $test_sh, skipping"
        continue
    fi

    # Derive mount path from file location, e.g.,
    # tests/wsgi/file_wrapper.py -> /test/wsgi/file-wrapper
    mount_path="/test/$(echo "${test_py#tests/}" | sed 's/\.py$//' | tr '_' '-')"

    echo "WSGIScriptAlias $mount_path $PROJECT_DIR/$test_py process-group=localhost:$PORT application-group=%{GLOBAL}" >> "$INCLUDE_FILE"

    # Append optional per-test Apache configuration (e.g., for
    # tests that need a <Location> override of a mod_wsgi
    # directive).
    test_conf="${test_sh%.sh}.conf"
    if [ -f "$test_conf" ]; then
        cat "$test_conf" >> "$INCLUDE_FILE"
    fi
done

echo "Starting test server on port $PORT..."
start_server "$INCLUDE_FILE"
echo ""

# Run each test file.
for test_sh in "${TEST_FILES[@]}"; do
    test_name="$(basename "${test_sh%.sh}")"
    echo "== $test_name =="
    source "$test_sh"
    echo ""
done

# Summary.
echo "========================================"
echo "Results: $PASS passed, $FAIL failed"
echo "========================================"

if [ $FAIL -gt 0 ]; then
    echo -e "\nFailures:$ERRORS"
    echo ""
    echo "Server error log (last 20 lines):"
    tail -20 "$SERVER_ROOT/error_log" 2>/dev/null
    exit 1
fi
