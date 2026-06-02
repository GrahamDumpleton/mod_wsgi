# Test WSGI start_response semantics.
#
# Sourced by scripts/run-tests.sh which provides:
#   BASE_URL, assert_status, assert_body_equals,
#   assert_header_equals, assert_header_count

URL="$BASE_URL/test/wsgi/start-response"

# ----- write() callable -----

assert_status "$URL/write" "200" \
    "write() callable endpoint returns 200"

assert_body_equals "$URL/write" "via-write-via-iter" \
    "write() callable content precedes returned iterable content"

assert_body_equals "$URL/write-before-return" "pre-mid-post1-post2" \
    "multiple write() calls interleave correctly with iterable return"

# ----- Non-tuple exc_info -----

assert_body_equals "$URL/non-tuple-exc-info" \
    "got:start_response() argument 'exc_info' must be a 3-tuple or None" \
    "non-tuple exc_info raises RuntimeError"

# ----- exc_info after headers sent -----

assert_status "$URL/exc-info-after-headers" "200" \
    "exc_info after headers sent keeps already-committed status (200)"

assert_body_equals "$URL/exc-info-after-headers" \
    "headers-sent-reraised:intentional-exc-info" \
    "exc_info after headers sent re-raises the supplied exception"

# ----- exc_info before headers sent replaces prior status/headers -----

assert_status "$URL/exc-info-before-headers" "418" \
    "exc_info before headers sent replaces status line"

assert_body_equals "$URL/exc-info-before-headers" \
    "second-headers-win" \
    "exc_info before headers sent replaces body content"

assert_header_equals "$URL/exc-info-before-headers" \
    "X-After" "second" \
    "exc_info before headers sent installs replacement headers"

assert_header_count "$URL/exc-info-before-headers" \
    "X-Before" "0" \
    "exc_info before headers sent discards original headers"

# ----- Double start_response without exc_info, before output -----
# PEP 3333 says start_response "must not be called without the
# optional exc_info argument if start_response() has already been
# called within the current invocation of the application",
# regardless of whether headers have been flushed. mod_wsgi is
# deliberately more tolerant here: when no output has been sent
# yet, a second start_response call simply replaces the previously
# recorded status line and headers. The strictness only kicks in
# once headers are committed to the wire (see the
# /double-no-exc-after-headers assertion below).

assert_status "$URL/double-no-exc-before-headers" "201" \
    "second start_response before output uses second status"

assert_header_count "$URL/double-no-exc-before-headers" \
    "X-First" "0" \
    "second start_response before output discards first headers"

assert_header_equals "$URL/double-no-exc-before-headers" \
    "X-Second" "2" \
    "second start_response before output installs second headers"

# ----- Double start_response without exc_info, after output -----

assert_body_equals "$URL/double-no-exc-after-headers" \
    "pre-err:start_response() called more than once without exc_info" \
    "second start_response without exc_info after output raises RuntimeError"

# ----- Invalid status lines -----

assert_body_equals "$URL/invalid-status?case=no-digits" \
    "ValueError:status code must be a 3 digit integer: b'OK';end" \
    "status line without any leading digits is rejected"

assert_body_equals "$URL/invalid-status?case=mixed" \
    "ValueError:status code must be a 3 digit integer: b'20X OK';end" \
    "status line with a non-digit in the code is rejected"

assert_body_equals "$URL/invalid-status?case=four-digits" \
    "ValueError:status code must be a 3 digit integer: b'2000 OK';end" \
    "status line with a 4-digit code is rejected"

assert_body_equals "$URL/invalid-status?case=no-space" \
    "ValueError:no space following status code: b'200OK';end" \
    "status line without a space after the 3-digit code is rejected"

assert_body_equals "$URL/invalid-status?case=control-char" \
    "ValueError:control character in status reason phrase: b'200 OK\r\nX-Injected: yes';end" \
    "status line with embedded CR/LF is rejected (prevents header injection)"

# ----- Invalid header entries -----

assert_body_equals "$URL/invalid-header?case=empty-name" \
    "ValueError:header name is empty;end" \
    "empty header name is rejected"

assert_body_equals "$URL/invalid-header?case=space-name" \
    "ValueError:space character in header name: b'X Foo';end" \
    "header name containing a space is rejected"

assert_body_equals "$URL/invalid-header?case=control-name" \
    "ValueError:control character in header name: b'X\tFoo';end" \
    "header name containing a control character (tab) is rejected"

assert_body_equals "$URL/invalid-header?case=cr-value" \
    "ValueError:carriage return/line feed character in header value: b'line1\r\nline2';end" \
    "header value containing CR is rejected (prevents header injection)"

assert_body_equals "$URL/invalid-header?case=lf-value" \
    "ValueError:carriage return/line feed character in header value: b'line1\nline2';end" \
    "header value containing LF is rejected (prevents header injection)"

assert_body_equals "$URL/invalid-header?case=non-string-name" \
    "TypeError:must be str, not int;end" \
    "non-string header name is rejected with TypeError"

assert_body_equals "$URL/invalid-header?case=non-latin1-value" \
    "UnicodeEncodeError:'latin-1' codec can't encode characters in position 0-1: ordinal not in range(256);end" \
    "header value with non-latin1 characters is rejected"

assert_body_equals "$URL/invalid-header?case=not-a-tuple" \
    "TypeError:each header must be a 2-tuple, not str;end" \
    "header list item that is not a tuple is rejected"

assert_body_equals "$URL/invalid-header?case=wrong-tuple-size" \
    "ValueError:each header must be a 2-tuple, got length 3;end" \
    "header tuple with more than two entries is rejected"

# ----- Invalid types for the headers argument itself -----

assert_body_equals "$URL/invalid-headers-type?case=string" \
    "TypeError:start_response() argument 2 must be list, not str;end" \
    "string passed as headers argument is rejected"

assert_body_equals "$URL/invalid-headers-type?case=tuple" \
    "TypeError:start_response() argument 2 must be list, not tuple;end" \
    "tuple passed as headers argument is rejected (must be list)"

assert_body_equals "$URL/invalid-headers-type?case=dict" \
    "TypeError:start_response() argument 2 must be list, not dict;end" \
    "dict passed as headers argument is rejected"
