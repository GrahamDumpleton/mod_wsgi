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
BASE_URL="http://localhost:$PORT"

PASS=0
FAIL=0
ERRORS=""

# ---- Pre-flight cleanup ----

# Stop any leftover server from a previous run.
if [ -f "$SERVER_ROOT/apachectl" ]; then
    "$SERVER_ROOT/apachectl" stop 2>/dev/null || true
fi

# Wait for the port to be free (httpd may take several seconds to
# shut down cleanly).
tries=0
while lsof -i :"$PORT" -t >/dev/null 2>&1; do
    tries=$((tries + 1))
    if [ $tries -gt 10 ]; then
        # Force kill anything still holding the port.
        lsof -i :"$PORT" -t 2>/dev/null | xargs kill -9 2>/dev/null || true
        sleep 1
        break
    fi
    sleep 1
done

# ---- Assertion helpers (available to test .sh files) ----

assert_status() {
    local url="$1"
    local expected_status="$2"
    local description="$3"

    local status
    status=$(curl -s -o /dev/null -w '%{http_code}' "$url")

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
    body=$(curl -s "$url")

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
    body=$(curl -s "$url")

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
    actual_length=$(curl -s "$url" | wc -c | tr -d ' ')

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

# ---- Server management ----

start_server() {
    local include_file="$1"

    rm -rf "$SERVER_ROOT"

    local setup_args=(
        tests/hello.wsgi
        --server-root "$SERVER_ROOT"
        --port "$PORT"
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

    # Wait for clean shutdown, then force kill if needed.
    local tries=0
    while lsof -i :"$PORT" -t >/dev/null 2>&1; do
        tries=$((tries + 1))
        if [ $tries -gt 10 ]; then
            lsof -i :"$PORT" -t 2>/dev/null | xargs kill -9 2>/dev/null || true
            sleep 1
            break
        fi
        sleep 1
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

# Build Apache include file mounting each test app.
INCLUDE_FILE=$(mktemp)
trap "rm -f $INCLUDE_FILE; stop_server" EXIT

# Grant Apache access to the tests directory.
cat >> "$INCLUDE_FILE" <<EOF
<Directory $PROJECT_DIR/tests>
    Require all granted
</Directory>
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
