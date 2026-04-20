# Test trusted proxy header processing.
#
# Sourced by scripts/run-tests.sh which provides:
#   BASE_URL, assert_body_equals, assert_body_equals_headers,
#   assert_body_contains_headers
#
# Four <Location> blocks in proxy_headers.conf each configure a
# different WSGITrustedProxyHeaders / WSGITrustedProxies
# combination. Assertions below target the path that matches the
# behaviour being exercised.

ROOT="$BASE_URL/test/wsgi/proxy-headers"

# ---------- 1. Basic: trusted headers, no trusted-proxies allowlist ----------
#
# When WSGITrustedProxies is unset every peer counts as a trusted
# proxy, and wsgi_process_forwarded_for takes the simple branch
# that uses the first entry of the X-Forwarded-For list verbatim
# (the last rightmost entries are left in HTTP_X_FORWARDED_FOR
# as-is).

BASIC="$ROOT/basic"

assert_body_equals_headers "$BASIC/get?key=REMOTE_ADDR" \
    "value=203.0.113.5;end" \
    "X-Forwarded-For rewrites REMOTE_ADDR to the first (client) entry when no trusted-proxies list is set" \
    -H "X-Forwarded-For: 203.0.113.5, 10.0.0.1"

assert_body_equals_headers "$BASIC/get?key=HTTP_X_FORWARDED_FOR" \
    "value=203.0.113.5, 10.0.0.1;end" \
    "HTTP_X_FORWARDED_FOR is left intact when no trusted-proxies list is set" \
    -H "X-Forwarded-For: 203.0.113.5, 10.0.0.1"

assert_body_equals_headers "$BASIC/get?key=HTTP_HOST" \
    "value=proxy.example.com;end" \
    "X-Forwarded-Host rewrites HTTP_HOST" \
    -H "X-Forwarded-Host: proxy.example.com"

# HTTPS handling: mod_wsgi sets the internal HTTPS subprocess_env
# entry when a trusted proxy-scheme header asserts SSL, but before
# handing the environ dict to the Python app it converts that into
# wsgi.url_scheme ("https" vs "http") and removes the HTTPS key
# (see wsgi_adapter.c). The assertions therefore target
# wsgi.url_scheme rather than HTTPS.

assert_body_equals_headers "$BASIC/get?key=wsgi.url_scheme" \
    "value=https;end" \
    "X-Forwarded-Proto: https yields wsgi.url_scheme=https" \
    -H "X-Forwarded-Proto: https"

assert_body_equals_headers "$BASIC/get?key=wsgi.url_scheme" \
    "value=http;end" \
    "X-Forwarded-Proto: http yields wsgi.url_scheme=http" \
    -H "X-Forwarded-Proto: http"

# Boolean-style scheme flags: X-Forwarded-SSL / X-Forwarded-HTTPS.

assert_body_equals_headers "$BASIC/get?key=wsgi.url_scheme" \
    "value=https;end" \
    "X-Forwarded-SSL: On yields wsgi.url_scheme=https" \
    -H "X-Forwarded-SSL: On"

assert_body_equals_headers "$BASIC/get?key=wsgi.url_scheme" \
    "value=https;end" \
    "X-Forwarded-SSL: true yields wsgi.url_scheme=https" \
    -H "X-Forwarded-SSL: true"

assert_body_equals_headers "$BASIC/get?key=wsgi.url_scheme" \
    "value=https;end" \
    "X-Forwarded-SSL: 1 yields wsgi.url_scheme=https" \
    -H "X-Forwarded-SSL: 1"

assert_body_equals_headers "$BASIC/get?key=wsgi.url_scheme" \
    "value=http;end" \
    "X-Forwarded-SSL: Off yields wsgi.url_scheme=http" \
    -H "X-Forwarded-SSL: Off"

assert_body_equals_headers "$BASIC/get?key=wsgi.url_scheme" \
    "value=http;end" \
    "X-Forwarded-HTTPS: false yields wsgi.url_scheme=http" \
    -H "X-Forwarded-HTTPS: false"

assert_body_equals_headers "$BASIC/get?key=wsgi.url_scheme" \
    "value=http;end" \
    "X-Forwarded-HTTPS: 0 yields wsgi.url_scheme=http" \
    -H "X-Forwarded-HTTPS: 0"

# SCRIPT_NAME rewriting via X-Script-Name / X-Forwarded-Script-Name.

assert_body_equals_headers "$BASIC/get?key=SCRIPT_NAME" \
    "value=/app;end" \
    "X-Script-Name rewrites SCRIPT_NAME" \
    -H "X-Script-Name: /app"

assert_body_equals_headers "$BASIC/get?key=mod_wsgi.mount_point" \
    "value=/app;end" \
    "X-Script-Name populates mod_wsgi.mount_point" \
    -H "X-Script-Name: /app"

assert_body_equals_headers "$BASIC/get?key=SCRIPT_NAME" \
    "value=/other;end" \
    "X-Forwarded-Script-Name rewrites SCRIPT_NAME" \
    -H "X-Forwarded-Script-Name: /other"

# Category trimming: once at least one header in a category is
# listed in WSGITrustedProxyHeaders, every other header in that
# category is stripped from the environ regardless of whether
# the client sent it. X-Forwarded-For is the only client-IP
# header in the trusted list here, so spoofed X-Client-IP /
# X-Real-IP values in the same category must be dropped.

assert_body_equals_headers "$BASIC/has?key=HTTP_X_CLIENT_IP" \
    "present=NO;end" \
    "X-Client-IP in same category as trusted X-Forwarded-For is stripped from environ" \
    -H "X-Forwarded-For: 203.0.113.5" \
    -H "X-Client-IP: 198.51.100.9"

assert_body_equals_headers "$BASIC/has?key=HTTP_X_REAL_IP" \
    "present=NO;end" \
    "X-Real-IP in same category as trusted X-Forwarded-For is stripped from environ" \
    -H "X-Forwarded-For: 203.0.113.5" \
    -H "X-Real-IP: 198.51.100.9"

assert_body_equals_headers "$BASIC/get?key=HTTP_X_FORWARDED_FOR" \
    "value=203.0.113.5;end" \
    "trusted X-Forwarded-For is kept while other category peers are stripped" \
    -H "X-Forwarded-For: 203.0.113.5" \
    -H "X-Client-IP: 198.51.100.9" \
    -H "X-Real-IP: 203.0.113.9"

# ---------- 2. Trusted-client: trusted-proxies allowlist includes loopback ----
#
# With WSGITrustedProxies set to 127.0.0.1 (the address every curl
# in this harness connects from), wsgi_process_forwarded_for walks
# the X-Forwarded-For chain from the right dropping entries that
# are themselves trusted proxies, and reports the first untrusted
# IP (closer to the real client) as REMOTE_ADDR.

TRUSTED="$ROOT/trusted-client"

assert_body_equals_headers "$TRUSTED/get?key=REMOTE_ADDR" \
    "value=203.0.113.5;end" \
    "X-Forwarded-For chain walk picks the IP just before the first trusted proxy as REMOTE_ADDR" \
    -H "X-Forwarded-For: 203.0.113.5, 127.0.0.1"

assert_body_equals_headers "$TRUSTED/get?key=HTTP_X_FORWARDED_FOR" \
    "value=203.0.113.5, 127.0.0.1;end" \
    "HTTP_X_FORWARDED_FOR is rewritten to start at the selected REMOTE_ADDR" \
    -H "X-Forwarded-For: 203.0.113.5, 127.0.0.1"

# When the whole forwarded chain is made up of trusted IPs, the
# walk runs off the left edge, first becomes 0, and REMOTE_ADDR
# ends up as the leftmost entry (items[0]).

assert_body_equals_headers "$TRUSTED/get?key=REMOTE_ADDR" \
    "value=127.0.0.1;end" \
    "all-trusted X-Forwarded-For chain leaves REMOTE_ADDR at the leftmost entry" \
    -H "X-Forwarded-For: 127.0.0.1, 127.0.0.1"

# When X-Forwarded-For contains no trusted entries the function
# falls into the "no trusted IP found" branch and uses the last
# entry (rightmost) for REMOTE_ADDR.

assert_body_equals_headers "$TRUSTED/get?key=REMOTE_ADDR" \
    "value=203.0.113.5;end" \
    "X-Forwarded-For without any trusted entries falls back to the rightmost IP" \
    -H "X-Forwarded-For: 198.51.100.9, 203.0.113.5"

# Other trusted-header categories are still rewritten when the
# client peer is trusted.

assert_body_equals_headers "$TRUSTED/get?key=HTTP_HOST" \
    "value=real.example.com;end" \
    "X-Forwarded-Host rewrites HTTP_HOST when peer is in WSGITrustedProxies" \
    -H "X-Forwarded-Host: real.example.com"

assert_body_equals_headers "$TRUSTED/get?key=wsgi.url_scheme" \
    "value=https;end" \
    "X-Forwarded-Proto rewrites wsgi.url_scheme when peer is in WSGITrustedProxies" \
    -H "X-Forwarded-Proto: https"

assert_body_equals_headers "$TRUSTED/get?key=SCRIPT_NAME" \
    "value=/mounted;end" \
    "X-Script-Name rewrites SCRIPT_NAME when peer is in WSGITrustedProxies" \
    -H "X-Script-Name: /mounted"

# ---------- 3. Untrusted client: peer not in WSGITrustedProxies ---------------
#
# Loopback is 127.0.0.1 but WSGITrustedProxies here is 10.99.99.99
# so the request is treated as coming directly from an untrusted
# client. Every header in a trusted-category is dropped and no
# REMOTE_ADDR / HTTP_HOST / HTTPS / SCRIPT_NAME rewriting happens.

UNTRUSTED="$ROOT/untrusted-client"

# Pin this assertion to an explicit IPv4 connect so the loopback
# address surfaced as REMOTE_ADDR is stable across systems where
# `localhost` might otherwise resolve to ::1 first.
UNTRUSTED_V4=$(printf '%s' "$UNTRUSTED" | sed 's#://localhost:#://127.0.0.1:#')

assert_body_equals_headers "$UNTRUSTED_V4/get?key=REMOTE_ADDR" \
    "value=127.0.0.1;end" \
    "untrusted peer: REMOTE_ADDR is left as the real connection IP (not the spoofed X-Forwarded-For)" \
    -H "X-Forwarded-For: 203.0.113.5" \
    -H "Host: localhost:9876"

assert_body_equals_headers "$UNTRUSTED/has?key=HTTP_X_FORWARDED_FOR" \
    "present=NO;end" \
    "untrusted peer: spoofed X-Forwarded-For is stripped from environ" \
    -H "X-Forwarded-For: 203.0.113.5"

assert_body_equals_headers "$UNTRUSTED/has?key=HTTPS" \
    "present=NO;end" \
    "untrusted peer: X-Forwarded-Proto does not set HTTPS" \
    -H "X-Forwarded-Proto: https"

assert_body_equals_headers "$UNTRUSTED/has?key=HTTP_X_FORWARDED_PROTO" \
    "present=NO;end" \
    "untrusted peer: spoofed X-Forwarded-Proto is stripped from environ" \
    -H "X-Forwarded-Proto: https"

assert_body_equals_headers "$UNTRUSTED/get?key=HTTP_HOST" \
    "value=localhost:9876;end" \
    "untrusted peer: HTTP_HOST is left as the real Host header value" \
    -H "X-Forwarded-Host: spoof.example.com"

assert_body_equals_headers "$UNTRUSTED/has?key=HTTP_X_FORWARDED_HOST" \
    "present=NO;end" \
    "untrusted peer: spoofed X-Forwarded-Host is stripped from environ" \
    -H "X-Forwarded-Host: spoof.example.com"

assert_body_equals_headers "$UNTRUSTED/get?key=SCRIPT_NAME" \
    "value=/test/wsgi/proxy-headers;end" \
    "untrusted peer: SCRIPT_NAME is left as the Apache-assigned mount point" \
    -H "X-Script-Name: /spoof"

assert_body_equals_headers "$UNTRUSTED/has?key=HTTP_X_SCRIPT_NAME" \
    "present=NO;end" \
    "untrusted peer: spoofed X-Script-Name is stripped from environ" \
    -H "X-Script-Name: /spoof"

# ---------- 4. Partial: only X-Forwarded-For is trusted ----------------------
#
# No other proxy-style headers are opted-in, so headers from the
# host/scheme/script-name categories are left on the environ as
# ordinary HTTP_* entries without any rewriting of the associated
# CGI variables.

PARTIAL="$ROOT/partial"

assert_body_equals_headers "$PARTIAL/get?key=REMOTE_ADDR" \
    "value=203.0.113.5;end" \
    "partial config: X-Forwarded-For still rewrites REMOTE_ADDR" \
    -H "X-Forwarded-For: 203.0.113.5"

assert_body_equals_headers "$PARTIAL/get?key=HTTP_HOST" \
    "value=localhost:9876;end" \
    "partial config: X-Forwarded-Host does NOT rewrite HTTP_HOST when not trusted" \
    -H "X-Forwarded-Host: proxy.example.com"

assert_body_equals_headers "$PARTIAL/get?key=HTTP_X_FORWARDED_HOST" \
    "value=proxy.example.com;end" \
    "partial config: un-trusted X-Forwarded-Host still surfaces as HTTP_X_FORWARDED_HOST" \
    -H "X-Forwarded-Host: proxy.example.com"

assert_body_equals_headers "$PARTIAL/has?key=HTTPS" \
    "present=NO;end" \
    "partial config: X-Forwarded-Proto does NOT set HTTPS when not trusted" \
    -H "X-Forwarded-Proto: https"

assert_body_equals_headers "$PARTIAL/get?key=HTTP_X_FORWARDED_PROTO" \
    "value=https;end" \
    "partial config: un-trusted X-Forwarded-Proto still surfaces as HTTP_X_FORWARDED_PROTO" \
    -H "X-Forwarded-Proto: https"

assert_body_equals_headers "$PARTIAL/get?key=SCRIPT_NAME" \
    "value=/test/wsgi/proxy-headers;end" \
    "partial config: X-Script-Name does NOT rewrite SCRIPT_NAME when not trusted" \
    -H "X-Script-Name: /app"

assert_body_equals_headers "$PARTIAL/get?key=HTTP_X_SCRIPT_NAME" \
    "value=/app;end" \
    "partial config: un-trusted X-Script-Name still surfaces as HTTP_X_SCRIPT_NAME" \
    -H "X-Script-Name: /app"

# ---------- 5. Empty list entries in X-Forwarded-For (RFC 9110 §5.6.1) -------
#
# RFC 9110 §5.6.1 requires recipients to parse and ignore a
# reasonable number of empty list elements in comma-separated
# header field values. These assertions codify the spec-compliant
# behaviour expected from wsgi_process_forwarded_for for inputs
# like "a, , b", "a,,b", "a, b,", ", a, b" and "a, , , b".

# ---- Trusted-proxies branch (chain walk) ----
#
# With the loopback peer listed in WSGITrustedProxies, the chain
# walk must skip empty entries rather than treating them as
# resolvable IPs. In every case below the rightmost real entry
# (127.0.0.1) is a trusted proxy, so REMOTE_ADDR should become
# 203.0.113.5 once the walk has stripped the trusted loopback
# entry from the tail.

assert_body_equals_headers "$TRUSTED/get?key=REMOTE_ADDR" \
    "value=203.0.113.5;end" \
    "empty middle entry (with spaces) in X-Forwarded-For is ignored during chain walk" \
    -H "X-Forwarded-For: 203.0.113.5, , 127.0.0.1"

assert_body_equals_headers "$TRUSTED/get?key=REMOTE_ADDR" \
    "value=203.0.113.5;end" \
    "empty middle entry (no whitespace) in X-Forwarded-For is ignored during chain walk" \
    -H "X-Forwarded-For: 203.0.113.5,,127.0.0.1"

assert_body_equals_headers "$TRUSTED/get?key=REMOTE_ADDR" \
    "value=203.0.113.5;end" \
    "trailing comma (empty trailing entry) in X-Forwarded-For is ignored during chain walk" \
    -H "X-Forwarded-For: 203.0.113.5, 127.0.0.1,"

assert_body_equals_headers "$TRUSTED/get?key=REMOTE_ADDR" \
    "value=203.0.113.5;end" \
    "leading empty entry in X-Forwarded-For is ignored during chain walk" \
    -H "X-Forwarded-For: , 203.0.113.5, 127.0.0.1"

assert_body_equals_headers "$TRUSTED/get?key=REMOTE_ADDR" \
    "value=203.0.113.5;end" \
    "multiple adjacent empty entries in X-Forwarded-For are ignored during chain walk" \
    -H "X-Forwarded-For: 203.0.113.5,  ,  , 127.0.0.1"

# ---- No-trusted-proxies branch (leftmost-wins) ----
#
# Without a trusted-proxies allowlist the first non-empty entry
# of X-Forwarded-For becomes REMOTE_ADDR; empty leading entries
# must be skipped rather than emitted as empty strings.

assert_body_equals_headers "$BASIC/get?key=REMOTE_ADDR" \
    "value=203.0.113.5;end" \
    "leading empty entry is skipped and leftmost non-empty X-Forwarded-For entry wins" \
    -H "X-Forwarded-For: , 203.0.113.5"

assert_body_equals_headers "$BASIC/get?key=REMOTE_ADDR" \
    "value=203.0.113.5;end" \
    "multiple leading empty entries are skipped and leftmost non-empty X-Forwarded-For entry wins" \
    -H "X-Forwarded-For: , , 203.0.113.5, 198.51.100.1"

assert_body_equals_headers "$BASIC/get?key=REMOTE_ADDR" \
    "value=203.0.113.5;end" \
    "trailing comma after single X-Forwarded-For entry is ignored (leftmost-wins branch)" \
    -H "X-Forwarded-For: 203.0.113.5,"
