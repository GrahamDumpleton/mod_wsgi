"""Test wsgi.file_wrapper with different scenarios.

Endpoints:

  /test/file-wrapper/basic
    Returns a known file via wsgi.file_wrapper. Tests the basic
    sendfile optimization path with a real file object.

  /test/file-wrapper/with-content-length
    Returns a file via wsgi.file_wrapper with an explicit
    Content-Length header set.

  /test/file-wrapper/partial
    Opens a file, seeks partway in, then returns it via
    wsgi.file_wrapper. Tests that the file offset is respected.

  /test/file-wrapper/iterable-fallback
    Returns a non-file object (io.BytesIO) via wsgi.file_wrapper.
    Since BytesIO has no real file descriptor, the sendfile
    optimization cannot be used and it falls back to iteration.
"""

import io
import os
import tempfile

# Create a temporary file with known content at module level so
# it persists for the lifetime of the process.

_test_content = b"file_wrapper test: SUCCESS\n" * 100
_test_file = tempfile.NamedTemporaryFile(delete=False)
_test_file.write(_test_content)
_test_file.flush()
_test_file_path = _test_file.name
_test_file.close()


def application(environ, start_response):
    path = environ.get("PATH_INFO", "/")

    if path == "/basic":
        return handle_basic(environ, start_response)
    elif path == "/with-content-length":
        return handle_with_content_length(environ, start_response)
    elif path == "/partial":
        return handle_partial(environ, start_response)
    elif path == "/iterable-fallback":
        return handle_iterable_fallback(environ, start_response)
    else:
        start_response("404 Not Found", [("Content-Type", "text/plain")])
        return [b"Unknown test path"]


def handle_basic(environ, start_response):
    f = open(_test_file_path, "rb")

    start_response("200 OK", [
        ("Content-Type", "text/plain"),
    ])

    return environ["wsgi.file_wrapper"](f, 8192)


def handle_with_content_length(environ, start_response):
    f = open(_test_file_path, "rb")

    start_response("200 OK", [
        ("Content-Type", "text/plain"),
        ("Content-Length", str(len(_test_content))),
    ])

    return environ["wsgi.file_wrapper"](f, 8192)


def handle_partial(environ, start_response):
    f = open(_test_file_path, "rb")

    # Seek past the first line.
    first_line = b"file_wrapper test: SUCCESS\n"
    f.seek(len(first_line))

    remaining = len(_test_content) - len(first_line)

    start_response("200 OK", [
        ("Content-Type", "text/plain"),
        ("Content-Length", str(remaining)),
    ])

    return environ["wsgi.file_wrapper"](f, 8192)


def handle_iterable_fallback(environ, start_response):
    content = b"file_wrapper iterable fallback: SUCCESS"
    buf = io.BytesIO(content)

    start_response("200 OK", [
        ("Content-Type", "text/plain"),
        ("Content-Length", str(len(content))),
    ])

    return environ["wsgi.file_wrapper"](buf, 8192)
