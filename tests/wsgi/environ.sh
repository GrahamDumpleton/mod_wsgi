# Test that request metadata reaches the WSGI environ dict.
#
# Sourced by scripts/run-tests.sh which provides:
#   BASE_URL, assert_body_equals, assert_body_equals_headers,
#   assert_body_contains_headers

URL="$BASE_URL/test/wsgi/environ"

# ----- Standard CGI variables -----

assert_body_equals "$URL/has?key=REQUEST_METHOD" \
    "present=YES;end" \
    "REQUEST_METHOD is present in environ"

assert_body_equals "$URL/get?key=REQUEST_METHOD" \
    "value=GET;end" \
    "REQUEST_METHOD reflects the HTTP method"

assert_body_equals "$URL/get?key=SERVER_PROTOCOL" \
    "value=HTTP/1.1;end" \
    "SERVER_PROTOCOL reflects the HTTP protocol version"

assert_body_equals "$URL/get?key=HTTP_HOST" \
    "value=localhost:9876;end" \
    "HTTP_HOST reflects the Host header"

# ----- SCRIPT_NAME vs PATH_INFO split at WSGIScriptAlias mount -----

assert_body_equals "$URL/get?key=SCRIPT_NAME" \
    "value=/test/wsgi/environ;end" \
    "SCRIPT_NAME matches the WSGIScriptAlias mount point"

assert_body_equals "$URL/get?key=PATH_INFO" \
    "value=/get;end" \
    "PATH_INFO is the URL path beneath the mount point"

assert_body_equals "$URL/get?key=QUERY_STRING" \
    "value=key=QUERY_STRING;end" \
    "QUERY_STRING reflects the request query string"

# ----- CONTENT_TYPE and CONTENT_LENGTH from request headers -----
#
# PEP 3333 §8.1 mandates that the Content-Type and Content-Length
# request headers surface in environ under the bare CGI keys
# (CONTENT_TYPE / CONTENT_LENGTH) rather than the HTTP_-prefixed
# form used for other request headers.

assert_post_body_equals_curl "$URL/get?key=CONTENT_TYPE" \
    "payload" \
    "value=application/x-custom;end" \
    "CONTENT_TYPE environ key reflects the request Content-Type header" \
    -H "Content-Type: application/x-custom"

assert_post_body_equals_curl "$URL/get?key=CONTENT_LENGTH" \
    "payload" \
    "value=7;end" \
    "CONTENT_LENGTH environ key reflects the request Content-Length header" \
    -H "Content-Type: application/x-custom"

assert_post_body_equals_curl "$URL/has?key=HTTP_CONTENT_TYPE" \
    "payload" \
    "present=NO;end" \
    "HTTP_CONTENT_TYPE is absent (Content-Type uses the bare CONTENT_TYPE key)" \
    -H "Content-Type: application/x-custom"

assert_post_body_equals_curl "$URL/has?key=HTTP_CONTENT_LENGTH" \
    "payload" \
    "present=NO;end" \
    "HTTP_CONTENT_LENGTH is absent (Content-Length uses the bare CONTENT_LENGTH key)" \
    -H "Content-Type: application/x-custom"

# ----- Custom request headers become HTTP_* keys -----

assert_body_equals_headers "$URL/get?key=HTTP_X_REQUEST_ID" \
    "value=req-abc-123;end" \
    "custom X-Request-Id reaches environ as HTTP_X_REQUEST_ID" \
    -H "X-Request-Id: req-abc-123"

assert_body_equals "$URL/has?key=HTTP_X_REQUEST_ID" \
    "present=NO;end" \
    "HTTP_X_REQUEST_ID is absent when client did not send the header"

assert_body_equals_headers "$URL/get?key=HTTP_X_WITH_DASHES" \
    "value=dash-test;end" \
    "X-With-Dashes header folds dashes to underscores in environ key" \
    -H "X-With-Dashes: dash-test"

assert_body_equals_headers "$URL/get?key=HTTP_X_MULTI" \
    "value=a, b;end" \
    "duplicate X-Multi request headers are combined as comma-separated value" \
    -H "X-Multi: a" \
    -H "X-Multi: b"

# ----- PATH is explicitly removed by Adapter_environ -----

assert_body_equals "$URL/has?key=PATH" \
    "present=NO;end" \
    "PATH is explicitly removed from the environ dict"

# ----- WSGI-specific keys -----

assert_body_equals "$URL/wsgi-version" \
    "version=(1, 0);end" \
    "wsgi.version tuple is (1, 0)"

assert_body_equals "$URL/get?key=wsgi.url_scheme" \
    "value=http;end" \
    "wsgi.url_scheme is 'http' for plain HTTP requests"

assert_body_equals "$URL/has?key=HTTPS" \
    "present=NO;end" \
    "HTTPS variable is absent for plain HTTP requests"

assert_body_equals "$URL/get?key=wsgi.multithread" \
    "value=True;end" \
    "wsgi.multithread is True (daemon group has threads=5)"

assert_body_equals "$URL/get?key=wsgi.run_once" \
    "value=False;end" \
    "wsgi.run_once is False"

assert_body_equals "$URL/get?key=wsgi.input_terminated" \
    "value=True;end" \
    "wsgi.input_terminated is True"

assert_body_equals "$URL/type?key=wsgi.input" \
    "type=mod_wsgi.Input;end" \
    "wsgi.input is a mod_wsgi.Input instance"

assert_body_equals "$URL/type?key=wsgi.errors" \
    "type=_io.TextIOWrapper;end" \
    "wsgi.errors is wrapped in an io.TextIOWrapper"

assert_body_equals "$URL/type?key=wsgi.file_wrapper" \
    "type=mod_wsgi.FileWrapper;end" \
    "wsgi.file_wrapper is the mod_wsgi.FileWrapper class"

assert_body_equals "$URL/type?key=wsgi.multiprocess" \
    "type=builtins.bool;end" \
    "wsgi.multiprocess is a bool"

# ----- PEP 3333 mandates native strings (str in Py3) for CGI -----
#
# Per PEP 3333 § 2.2, all CGI-environment keys and values in the
# environ dict must be of the native string type (str on Python 3).
# mod_wsgi decodes Apache's subprocess_env entries via
# PyUnicode_DecodeLatin1 / PyUnicode_DecodeFSDefault, so all CGI
# values should surface as str.

assert_body_equals "$URL/type?key=REQUEST_METHOD" \
    "type=builtins.str;end" \
    "REQUEST_METHOD environ value is a native str"

assert_body_equals "$URL/type?key=PATH_INFO" \
    "type=builtins.str;end" \
    "PATH_INFO environ value is a native str"

assert_body_equals "$URL/type?key=SCRIPT_NAME" \
    "type=builtins.str;end" \
    "SCRIPT_NAME environ value is a native str"

assert_body_equals "$URL/type?key=QUERY_STRING" \
    "type=builtins.str;end" \
    "QUERY_STRING environ value is a native str"

assert_body_equals "$URL/type?key=SERVER_PROTOCOL" \
    "type=builtins.str;end" \
    "SERVER_PROTOCOL environ value is a native str"

assert_body_equals "$URL/type?key=SERVER_NAME" \
    "type=builtins.str;end" \
    "SERVER_NAME environ value is a native str"

assert_body_equals "$URL/type?key=SERVER_PORT" \
    "type=builtins.str;end" \
    "SERVER_PORT environ value is a native str (not int)"

assert_body_equals_headers "$URL/type?key=HTTP_X_CUSTOM_STR" \
    "type=builtins.str;end" \
    "custom HTTP_* request header surfaces as str" \
    -H "X-Custom-Str: hello"

assert_body_equals "$URL/type?key=wsgi.url_scheme" \
    "type=builtins.str;end" \
    "wsgi.url_scheme is a native str"

# ----- mod_wsgi / apache metadata keys -----

assert_body_equals "$URL/has?key=mod_wsgi.version" \
    "present=YES;end" \
    "mod_wsgi.version is present"

assert_body_equals "$URL/has?key=mod_wsgi.thread_id" \
    "present=YES;end" \
    "mod_wsgi.thread_id is present"

assert_body_equals "$URL/has?key=mod_wsgi.thread_requests" \
    "present=YES;end" \
    "mod_wsgi.thread_requests is present"

assert_body_equals "$URL/has?key=mod_wsgi.total_requests" \
    "present=YES;end" \
    "mod_wsgi.total_requests is present"

assert_body_equals "$URL/has?key=apache.version" \
    "present=YES;end" \
    "apache.version is present"

# ----- HTTP_* key listing includes custom headers -----

assert_body_contains_headers "$URL/all-http" \
    "HTTP_X_ONE" \
    "custom X-One appears in /all-http listing when sent" \
    -H "X-One: 1"

assert_body_contains_headers "$URL/all-http" \
    "HTTP_X_TWO" \
    "custom X-Two appears in /all-http listing when sent" \
    -H "X-Two: 2"
