# Test custom response headers via start_response.
#
# Sourced by scripts/run-tests.sh which provides:
#   BASE_URL, assert_status, assert_header_equals, assert_header_count

URL="$BASE_URL/test/wsgi/headers"

# ----- Single custom X-* header -----

assert_status "$URL/custom" "200" \
    "single custom header endpoint returns 200"

assert_header_equals "$URL/custom" "X-Test-Custom" "hello-world" \
    "single custom X-* header reaches the client"

# ----- Multiple distinct custom X-* headers -----

assert_status "$URL/multiple-custom" "200" \
    "multiple custom headers endpoint returns 200"

assert_header_equals "$URL/multiple-custom" "X-Test-First" "one" \
    "first of multiple custom headers reaches the client"

assert_header_equals "$URL/multiple-custom" "X-Test-Second" "two" \
    "second of multiple custom headers reaches the client"

assert_header_equals "$URL/multiple-custom" "X-Test-Third" "three" \
    "third of multiple custom headers reaches the client"

# ----- Repeated header name -----

assert_status "$URL/repeated-custom" "200" \
    "repeated custom header endpoint returns 200"

# Apache/apr_table_add preserves both entries, and the HTTP output
# filter folds them into a single comma-separated field value per
# RFC 9110 § 5.3.
assert_header_equals "$URL/repeated-custom" "X-Test-Repeated" \
    "first-value, second-value" \
    "repeating the same header name preserves both values in the response"

# ----- WWW-Authenticate via err_headers_out -----

assert_status "$URL/www-authenticate" "401" \
    "WWW-Authenticate endpoint returns 401"

assert_header_equals "$URL/www-authenticate" "WWW-Authenticate" \
    'Basic realm="test"' \
    "WWW-Authenticate header is propagated via err_headers_out"

# ----- Many headers exercising the emission loop -----

assert_status "$URL/many" "200" \
    "many headers endpoint returns 200"

assert_header_equals "$URL/many" "X-Many-01" "value-1" \
    "first of 25 custom headers reaches the client"

assert_header_equals "$URL/many" "X-Many-13" "value-13" \
    "middle of 25 custom headers reaches the client"

assert_header_equals "$URL/many" "X-Many-25" "value-25" \
    "last of 25 custom headers reaches the client"

# ----- Invalid Content-Length rejected by the adapter -----

assert_status "$URL/invalid-content-length" "500" \
    "non-numeric Content-Length produces a 500 response"
