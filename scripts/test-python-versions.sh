#!/bin/bash

# Test mod_wsgi build/install across Python versions using uv.
# Usage:
#   ./scripts/test-python-versions.sh              # test all versions
#   ./scripts/test-python-versions.sh 3.12 3.13    # test specific versions

set -e

VERSIONS=("${@:-3.10 3.11 3.12 3.13 3.14}")

PASS=()
FAIL=()

for version in ${VERSIONS[@]}; do
    echo "========================================"
    echo "Testing Python $version"
    echo "========================================"

    # Clean up any existing venv.
    rm -rf .venv

    # Create venv for this Python version.
    if ! uv venv --python "$version" 2>&1; then
        echo "SKIP: Python $version not available"
        continue
    fi

    # Install mod_wsgi in development mode.
    if ! uv pip install -e . --no-cache 2>&1; then
        echo "FAIL: Python $version - install failed"
        FAIL+=("$version")
        continue
    fi

    # Set up server root for this test.
    rm -rf /tmp/mod_wsgi-test

    uv run mod_wsgi-express setup-server tests/environ.wsgi \
        --server-root /tmp/mod_wsgi-test --log-level info

    # Start server and test it responds.
    /tmp/mod_wsgi-test/apachectl start

    # Wait for server to be ready.
    TRIES=0
    while [ ! -f /tmp/mod_wsgi-test/httpd.pid ]; do
        TRIES=$((TRIES + 1))
        if [ $TRIES -gt 15 ]; then
            echo "FAIL: Python $version - server did not start"
            cat /tmp/mod_wsgi-test/error_log 2>/dev/null
            FAIL+=("$version")
            continue 2
        fi
        sleep 1
    done

    sleep 1

    if curl --silent --fail http://localhost:8000 > /dev/null 2>&1; then
        echo "PASS: Python $version"
        PASS+=("$version")
    else
        echo "FAIL: Python $version - no response"
        cat /tmp/mod_wsgi-test/error_log 2>/dev/null
        FAIL+=("$version")
    fi

    # Stop server.
    /tmp/mod_wsgi-test/apachectl stop 2>/dev/null || true
    rm -rf /tmp/mod_wsgi-test
done

# Clean up.
rm -rf .venv

echo ""
echo "========================================"
echo "Results"
echo "========================================"
echo "PASS: ${PASS[*]:-none}"
echo "FAIL: ${FAIL[*]:-none}"

if [ ${#FAIL[@]} -gt 0 ]; then
    exit 1
fi
