# Test that request bodies are read back intact in daemon mode with
# the deferred-content handshake both enabled and disabled.
#
# Sourced by scripts/run-tests.sh which provides BASE_URL, PORT,
# CURL_COMMON, PASS, FAIL and ERRORS.
#
# The /no-handshake mount routes to a dedicated daemon group with
# queue-timeout=0 and has WSGIScriptReloading Off (see
# request_body.conf and dispatch.py), which disables the "200 Continue"
# handshake. The Apache child then sends the environment frame and the
# proxied request body back to back, exercising the daemon frame-read
# path that must not swallow the leading body bytes. Before the fix in
# wsgi_read_strings every body read on this path failed with:
#   OSError: mod_wsgi request data read error: Partial results are
#   valid but processing is incomplete
# The normal mount keeps the handshake on and confirms the same app
# reads bodies correctly through the standard path.

# Post a random body of $2 bytes to URL $1 and check the app reports
# the expected serving process group ($3) and a byte-exact SHA-256 of
# what was sent. The body is written to a file so binary content
# (including NUL bytes) survives, and the digest is taken of the bytes
# actually sent so the check is independent of how they were generated.
assert_request_body() {
    local url="$1"
    local size="$2"
    local expect_group="$3"
    local description="$4"

    local tmp
    tmp=$(mktemp)
    # BSD head rejects "-c 0", so produce the empty body directly.
    if [ "$size" -gt 0 ]; then
        head -c "$size" /dev/urandom > "$tmp"
    else
        : > "$tmp"
    fi

    local sent_len sent_sha
    sent_len=$(wc -c < "$tmp" | tr -d ' ')
    sent_sha=$(openssl dgst -sha256 "$tmp" | awk '{print $NF}')

    local expected="group=$expect_group len=$sent_len sha256=$sent_sha"

    local body
    body=$(curl "${CURL_COMMON[@]}" -s -X POST --data-binary @"$tmp" \
        -H "Content-Type: application/octet-stream" "$url")
    rm -f "$tmp"

    if [ "$body" = "$expected" ]; then
        echo "  PASS: $description"
        PASS=$((PASS + 1))
    else
        echo "  FAIL: $description (expected '$expected', got '$body')"
        FAIL=$((FAIL + 1))
        ERRORS="$ERRORS\n  FAIL: $description"
    fi
}

NORMAL="$BASE_URL/test/wsgi/request-body"
NOHS="$BASE_URL/test/wsgi/request-body/no-handshake"

# Sizes bracket the daemon frame-read boundary (the regression lost
# body bytes that arrived in the same read as the environment frame)
# and include an empty body and a body too large to read in one go.
SIZES="0 1 11 1024 8192 65536"

# Normal case: handshake enabled via the shared daemon group.
for size in $SIZES; do
    assert_request_body "$NORMAL" "$size" "localhost:$PORT" \
        "handshake on: ${size}-byte body read intact"
done

# Regression case: handshake disabled via the dedicated daemon group.
for size in $SIZES; do
    assert_request_body "$NOHS" "$size" "request-body-no-handshake" \
        "handshake off: ${size}-byte body read intact"
done
