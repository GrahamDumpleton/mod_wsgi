"""Test logging to sys.stdout, sys.stderr, and wsgi.errors.

Endpoints:

  /test/wsgi/logging/stdout
    Writes a marker string to sys.stdout via print(). In mod_wsgi,
    sys.stdout is redirected to the Apache error log.

  /test/wsgi/logging/stderr
    Writes a marker string to sys.stderr via print(). In mod_wsgi,
    sys.stderr is redirected to the Apache error log.

  /test/wsgi/logging/wsgi-errors
    Writes a marker string to environ['wsgi.errors']. This is the
    per-request error log stream defined by the WSGI spec.

  /test/wsgi/logging/all
    Writes distinct marker strings to all three streams in a single
    request to verify they can all be used together.

  /test/wsgi/logging/multiline
    Writes a multi-line message to wsgi.errors to verify line
    buffering splits lines correctly.

  /test/wsgi/logging/flush
    Writes to wsgi.errors and explicitly flushes.

  /test/wsgi/logging/wsgi-errors-writelines
    Calls wsgi.errors.writelines() with a list of pre-terminated
    lines. PEP 3333 requires wsgi.errors to support writelines().

  /test/wsgi/logging/wsgi-errors-buffer
    Writes bytes, bytearray and memoryview objects to the underlying
    binary stream wsgi.errors.buffer. The memoryview case is the
    regression from issue #863, where it raised TypeError because the
    binary write() only accepted read-only bytes-like objects without a
    releasebuffer slot.

  /test/wsgi/logging/wsgi-errors-buffer-writelines
    Calls writelines() on the binary stream wsgi.errors.buffer with an
    iterable of mixed bytes-like objects. Unlike writelines() on
    wsgi.errors (which is the io.TextIOWrapper), this exercises the
    mod_wsgi.Log.writelines() C implementation directly.
"""

import sys


def application(environ, start_response):
    path = environ.get("PATH_INFO", "/")

    if path == "/stdout":
        return handle_stdout(environ, start_response)
    elif path == "/stderr":
        return handle_stderr(environ, start_response)
    elif path == "/wsgi-errors":
        return handle_wsgi_errors(environ, start_response)
    elif path == "/all":
        return handle_all(environ, start_response)
    elif path == "/multiline":
        return handle_multiline(environ, start_response)
    elif path == "/flush":
        return handle_flush(environ, start_response)
    elif path == "/wsgi-errors-writelines":
        return handle_wsgi_errors_writelines(environ, start_response)
    elif path == "/wsgi-errors-buffer":
        return handle_wsgi_errors_buffer(environ, start_response)
    elif path == "/wsgi-errors-buffer-writelines":
        return handle_wsgi_errors_buffer_writelines(environ, start_response)
    else:
        start_response("404 Not Found", [("Content-Type", "text/plain")])
        return [b"Unknown test path"]


def handle_stdout(environ, start_response):
    print("MARKER_STDOUT_TEST_12345")

    start_response("200 OK", [("Content-Type", "text/plain")])
    return [b"stdout done"]


def handle_stderr(environ, start_response):
    print("MARKER_STDERR_TEST_12345", file=sys.stderr)

    start_response("200 OK", [("Content-Type", "text/plain")])
    return [b"stderr done"]


def handle_wsgi_errors(environ, start_response):
    environ["wsgi.errors"].write("MARKER_WSGIERRORS_TEST_12345\n")

    start_response("200 OK", [("Content-Type", "text/plain")])
    return [b"wsgi.errors done"]


def handle_all(environ, start_response):
    print("MARKER_ALL_STDOUT_67890")
    print("MARKER_ALL_STDERR_67890", file=sys.stderr)
    environ["wsgi.errors"].write("MARKER_ALL_WSGIERRORS_67890\n")

    start_response("200 OK", [("Content-Type", "text/plain")])
    return [b"all done"]


def handle_multiline(environ, start_response):
    errors = environ["wsgi.errors"]
    errors.write("MARKER_MULTI_LINE1_11111\n")
    errors.write("MARKER_MULTI_LINE2_11111\n")

    start_response("200 OK", [("Content-Type", "text/plain")])
    return [b"multiline done"]


def handle_flush(environ, start_response):
    errors = environ["wsgi.errors"]
    errors.write("MARKER_FLUSH_TEST_22222\n")
    errors.flush()

    start_response("200 OK", [("Content-Type", "text/plain")])
    return [b"flush done"]


def handle_wsgi_errors_writelines(environ, start_response):
    # PEP 3333 requires wsgi.errors to support writelines(). The
    # convention (matching file objects) is that writelines takes
    # an iterable of strings and does NOT add line terminators,
    # so each element includes its own "\n".
    errors = environ["wsgi.errors"]
    errors.writelines([
        "MARKER_WRITELINES_A_33333\n",
        "MARKER_WRITELINES_B_33333\n",
        "MARKER_WRITELINES_C_33333\n",
    ])

    start_response("200 OK", [("Content-Type", "text/plain")])
    return [b"writelines done"]


def handle_wsgi_errors_buffer(environ, start_response):
    # wsgi.errors is an io.TextIOWrapper; its .buffer attribute is the
    # underlying binary stream. It must accept any bytes-like object.
    # The memoryview case is the issue #863 regression.
    buffer = environ["wsgi.errors"].buffer
    buffer.write(b"MARKER_BUFFER_BYTES_44444\n")
    buffer.write(bytearray(b"MARKER_BUFFER_BYTEARRAY_44444\n"))
    buffer.write(memoryview(b"MARKER_BUFFER_MEMORYVIEW_44444\n"))
    buffer.flush()

    start_response("200 OK", [("Content-Type", "text/plain")])
    return [b"buffer done"]


def handle_wsgi_errors_buffer_writelines(environ, start_response):
    # writelines() on the binary .buffer goes through the
    # mod_wsgi.Log.writelines() C implementation, not the
    # io.TextIOWrapper one. Each element must be a bytes-like object;
    # here we mix bytes, bytearray and memoryview.
    buffer = environ["wsgi.errors"].buffer
    buffer.writelines([
        b"MARKER_BUFFER_WL_BYTES_55555\n",
        bytearray(b"MARKER_BUFFER_WL_BYTEARRAY_55555\n"),
        memoryview(b"MARKER_BUFFER_WL_MEMORYVIEW_55555\n"),
    ])
    buffer.flush()

    start_response("200 OK", [("Content-Type", "text/plain")])
    return [b"buffer writelines done"]
