# Test HTTP method handling in REQUEST_METHOD.
#
# Sourced by scripts/run-tests.sh which provides:
#   BASE_URL, assert_body_equals, assert_header_equals,
#   assert_header_equals_curl

URL="$BASE_URL/test/wsgi/method"

# ----- Methods that pass through unchanged -----

assert_body_equals "$URL/method" "method=GET;end" \
    "GET appears as GET in REQUEST_METHOD"

assert_header_equals_curl "$URL/method" "X-Method-Seen" "POST" \
    "POST appears as POST in REQUEST_METHOD" \
    -X POST

assert_header_equals_curl "$URL/method" "X-Method-Seen" "PUT" \
    "PUT appears as PUT in REQUEST_METHOD" \
    -X PUT

assert_header_equals_curl "$URL/method" "X-Method-Seen" "DELETE" \
    "DELETE appears as DELETE in REQUEST_METHOD" \
    -X DELETE

assert_header_equals_curl "$URL/method" "X-Method-Seen" "PATCH" \
    "PATCH appears as PATCH in REQUEST_METHOD" \
    -X PATCH

# ----- HEAD handling under WSGIMapHEADToGET Auto (default) -----
#
# mod_wsgi's default is Auto, which only remaps HEAD to GET when a
# content output filter (e.g. mod_deflate) is in the filter chain,
# so that filter processing still sees a real body. This test
# server has no such filter, so HEAD passes through to the app as
# HEAD under the default.

assert_header_equals_curl "$URL/method" "X-Method-Seen" "HEAD" \
    "HEAD with default Auto mapping and no content filter reaches app as HEAD" \
    -X HEAD

# ----- WSGIMapHEADToGET On unconditionally remaps HEAD -----

assert_header_equals_curl "$URL/head-to-get" "X-Method-Seen" "GET" \
    "HEAD with WSGIMapHEADToGET On reaches app as GET" \
    -X HEAD

# GET on the same endpoint is obviously unaffected.
assert_body_equals "$URL/head-to-get" "method=GET;end" \
    "GET on WSGIMapHEADToGET On endpoint is still GET"

# ----- WSGIMapHEADToGET Off explicitly disables the remap -----

assert_header_equals_curl "$URL/head-passthrough" "X-Method-Seen" "HEAD" \
    "HEAD with WSGIMapHEADToGET Off reaches app as HEAD" \
    -X HEAD

assert_body_equals "$URL/head-passthrough" "method=GET;end" \
    "GET on WSGIMapHEADToGET Off endpoint is still GET"
