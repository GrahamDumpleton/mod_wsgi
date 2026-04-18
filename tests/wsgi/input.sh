# Test reading request bodies via wsgi.input.
#
# Sourced by scripts/run-tests.sh which provides:
#   BASE_URL, assert_post_body_equals

URL="$BASE_URL/test/wsgi/input"

# ----- read() with no argument -----

assert_post_body_equals "$URL/read-all" \
    "hello world" \
    "data=hello world;end" \
    "read() with no arg returns full body"

assert_post_body_equals "$URL/read-all" \
    "" \
    "data=;end" \
    "read() on empty body returns empty bytes"

assert_post_body_equals "$URL/read-all" \
    $'line1\nline2\nline3' \
    $'data=line1\nline2\nline3;end' \
    "read() returns body verbatim including embedded newlines"

# ----- read(N) -----

assert_post_body_equals "$URL/read-sized" \
    "abcdefghijklmno" \
    "first=abcdefghij,rest=klmno;end" \
    "read(10) then read() splits body at the requested size"

# ----- read(N) in a loop -----

assert_post_body_equals "$URL/read-chunks" \
    "this is a long body that spans chunks" \
    "chunks=6,data=this is a long body that spans chunks;end" \
    "read(7) in a loop reads entire body across multiple chunks"

# ----- read(0) -----

assert_post_body_equals "$URL/read-zero" \
    "hello" \
    "zero_len=0,rest=hello;end" \
    "read(0) returns empty bytes without consuming input"

# ----- read after EOF -----

assert_post_body_equals "$URL/read-past-eof" \
    "abc" \
    "first_len=3,second_len=0;end" \
    "read() after EOF returns empty bytes"

# ----- readline() -----

assert_post_body_equals "$URL/readline" \
    $'line1\nline2\nline3' \
    "count=3,lines=line1|line2|line3;end" \
    "readline() yields each line until empty at EOF"

assert_post_body_equals "$URL/readline" \
    $'a\nb\nc\n' \
    "count=3,lines=a|b|c;end" \
    "readline() with trailing newline yields correct line count"

# ----- readline(N) -----

assert_post_body_equals "$URL/readline-sized" \
    "abcdefghijklm" \
    "first=abcde,second=fghij,rest=klm;end" \
    "readline(5) caps at 5 bytes when no newline is in range"

assert_post_body_equals "$URL/readline-sized" \
    $'ab\ncdefghijklm' \
    $'first=ab\n,second=cdefg,rest=hijklm;end' \
    "readline(5) stops at newline and stashes the residual for next call"

# ----- readlines() -----

assert_post_body_equals "$URL/readlines" \
    $'aa\nbb\ncc' \
    "count=3,lines=aa|bb|cc;end" \
    "readlines() returns every line"

# ----- readlines(hint) -----

assert_post_body_equals "$URL/readlines-hint" \
    $'xx\nyy\nzz' \
    "count=1,lines=xx;end" \
    "readlines(hint) stops after the first line exceeds the hint"

# ----- iteration -----

assert_post_body_equals "$URL/iterate" \
    $'p\nq\nr' \
    "count=3,lines=p|q|r;end" \
    "iterating wsgi.input yields each line"
