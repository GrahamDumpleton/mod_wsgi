URL="$BASE_URL/test/wsgi/authnz"

# ---- Basic authentication (WSGIAuthUserScript + AuthBasicProvider wsgi) ----

assert_status "$URL/basic" 401 \
    "basic auth without credentials returns 401"

assert_header_equals "$URL/basic" "WWW-Authenticate" \
    'Basic realm="Basic Area"' \
    "basic auth 401 response advertises Basic realm"

assert_status_curl "$URL/basic" 200 \
    "basic auth with valid credentials returns 200" \
    -u spy:secret

assert_body_contains_headers "$URL/basic" "user=spy;auth_type=Basic;end" \
    "basic auth success propagates REMOTE_USER and AUTH_TYPE to the WSGI app" \
    -u spy:secret

assert_status_curl "$URL/basic" 401 \
    "basic auth with wrong password returns 401" \
    -u spy:wrong

assert_status_curl "$URL/basic" 401 \
    "basic auth with unknown user returns 401" \
    -u nobody:whatever

# ---- Digest authentication (WSGIAuthUserScript + AuthDigestProvider wsgi) ----

assert_status "$URL/digest" 401 \
    "digest auth without credentials returns 401"

assert_status_curl "$URL/digest" 200 \
    "digest auth with valid credentials returns 200" \
    --digest -u spy:secret

assert_body_contains_headers "$URL/digest" "user=spy;auth_type=Digest;end" \
    "digest auth success propagates REMOTE_USER and AUTH_TYPE to the WSGI app" \
    --digest -u spy:secret

# ---- Group authorisation (WSGIAuthGroupScript + Require wsgi-group) ----

assert_status_curl "$URL/group" 200 \
    "group auth: user in required group is allowed" \
    -u spy:secret

assert_body_contains_headers "$URL/group" "user=spy;auth_type=Basic;end" \
    "group auth success propagates REMOTE_USER to the WSGI app" \
    -u spy:secret

# Apache returns 401 (not 403) when authn succeeds but the Require
# line denies access, so the user can retry with different
# credentials. This is Apache's default; AuthzSendForbiddenOnFailure
# would flip it to 403. Assert 401 to match out-of-box behaviour.
assert_status_curl "$URL/group" 401 \
    "group auth: authenticated user not in required group is denied" \
    -u citizen:secret

assert_status_curl "$URL/group" 401 \
    "group auth: wrong password rejected before group check (401 not 403)" \
    -u spy:wrong

# ---- Host access control (WSGIAccessScript / allow_access) ----

assert_status "$URL/allow" 200 \
    "access script allowing the request lets the WSGI app run"

assert_body_contains "$URL/allow" "user=-;auth_type=-;end" \
    "allowed request reaches the WSGI app with no auth context"

assert_status "$URL/deny" 403 \
    "access script denying the request returns 403 before the WSGI app runs"
