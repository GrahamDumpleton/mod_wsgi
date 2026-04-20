# Test that SSL markers reach the WSGI environ dict correctly.
#
# The harness starts the test httpd with both an HTTP listener
# (port $PORT) and an HTTPS listener (port $HTTPS_PORT) backed by a
# throwaway self-signed cert, with --ssl-environment turned on so
# mod_ssl populates HTTPS=on and the SSL_* entries via
# SSLOptions +StdEnvVars.
#
# Sourced by scripts/run-tests.sh which provides:
#   BASE_URL, HTTPS_BASE_URL, assert_body_equals_headers,
#   assert_body_equals, assert_status_curl

HTTP_URL="$BASE_URL/test/wsgi/https"
HTTPS_URL="$HTTPS_BASE_URL/test/wsgi/https"

# ---------- wsgi.url_scheme reflects the actual request scheme ----------
#
# wsgi_adapter.c derives wsgi.url_scheme from the HTTPS entry in
# subprocess_env. For an HTTPS connection that entry is populated
# by the ssl_is_https optional function retrieved in
# wsgi_environ_child_init; for a plain HTTP connection no HTTPS is
# set and the scheme falls through to "http".

assert_body_equals_headers "$HTTPS_URL/get?key=wsgi.url_scheme" \
    "value=https;end" \
    "wsgi.url_scheme is 'https' for requests over the HTTPS listener" \
    -k

assert_body_equals "$HTTP_URL/get?key=wsgi.url_scheme" \
    "value=http;end" \
    "wsgi.url_scheme is 'http' for requests over the HTTP listener"

# ---------- HTTPS key is stripped from the WSGI environ dict ----------
#
# Per PEP 3333 the app should rely on wsgi.url_scheme rather than a
# CGI-style HTTPS variable, so Adapter_environ explicitly deletes
# the HTTPS key after using it to derive the scheme. The assertion
# must pass regardless of whether the value originated from mod_ssl
# (on HTTPS) or from a trusted proxy header (covered elsewhere).

assert_body_equals_headers "$HTTPS_URL/has?key=HTTPS" \
    "present=NO;end" \
    "HTTPS key is stripped from the environ dict on an HTTPS request" \
    -k

assert_body_equals "$HTTP_URL/has?key=HTTPS" \
    "present=NO;end" \
    "HTTPS key is absent from the environ dict on a plain HTTP request"

# ---------- SERVER_PORT reflects the listener the request arrived on ----

assert_body_equals_headers "$HTTPS_URL/get?key=SERVER_PORT" \
    "value=$HTTPS_PORT;end" \
    "SERVER_PORT on HTTPS is the HTTPS listener port" \
    -k

assert_body_equals "$HTTP_URL/get?key=SERVER_PORT" \
    "value=$PORT;end" \
    "SERVER_PORT on HTTP is the HTTP listener port"

# ---------- SSL_* standard env vars surface when --ssl-environment is on -
#
# SSLOptions +StdEnvVars (emitted by mod_wsgi-express when
# --ssl-environment is passed) makes mod_ssl populate the standard
# set of SSL_PROTOCOL / SSL_CIPHER / SSL_SERVER_* subprocess_env
# entries on every HTTPS request. These are not filtered out by
# Adapter_environ so they should reach the WSGI environ dict.

assert_body_equals_headers "$HTTPS_URL/has?key=SSL_PROTOCOL" \
    "present=YES;end" \
    "SSL_PROTOCOL is present in the environ on an HTTPS request" \
    -k

assert_body_equals_headers "$HTTPS_URL/has?key=SSL_CIPHER" \
    "present=YES;end" \
    "SSL_CIPHER is present in the environ on an HTTPS request" \
    -k

assert_body_equals_headers "$HTTPS_URL/type?key=SSL_PROTOCOL" \
    "type=builtins.str;end" \
    "SSL_PROTOCOL environ value is a native str" \
    -k

# Plain HTTP requests must not expose any SSL_* values, since no
# SSL handshake happened.

assert_body_equals "$HTTP_URL/has?key=SSL_PROTOCOL" \
    "present=NO;end" \
    "SSL_PROTOCOL is absent from the environ on a plain HTTP request"

assert_body_equals "$HTTP_URL/has?key=SSL_CIPHER" \
    "present=NO;end" \
    "SSL_CIPHER is absent from the environ on a plain HTTP request"
