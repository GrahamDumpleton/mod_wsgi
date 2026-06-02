"""Test reading request bodies via wsgi.input.

Endpoints:

  /test/wsgi/input/read-all
    Call read() with no argument and echo the body.

  /test/wsgi/input/read-sized
    Call read(10) then read() and report both halves.

  /test/wsgi/input/read-chunks
    Call read(7) in a loop until EOF, report chunk count and
    concatenated data.

  /test/wsgi/input/read-zero
    Call read(0) first (must not consume input), then read() for
    the remainder.

  /test/wsgi/input/read-past-eof
    Call read() twice; the second call must return empty bytes
    without error.

  /test/wsgi/input/readline
    Iterate with readline() until empty bytes and report lines.

  /test/wsgi/input/readline-sized
    Call readline(5) twice then read() to exercise the size cap
    and the residual-buffer fast path.

  /test/wsgi/input/readlines
    Call readlines() with no hint.

  /test/wsgi/input/readlines-hint
    Call readlines(1) — the hint is smaller than the first line
    so readlines() must stop after returning one entry.

  /test/wsgi/input/iterate
    Iterate the input object directly (tp_iter / tp_iternext).

Every response is suffixed with ";end" so shell command substitution
does not strip a trailing newline from the user-supplied content.
"""


def application(environ, start_response):
    path = environ.get("PATH_INFO", "/")

    handlers = {
        "/read-all": handle_read_all,
        "/read-sized": handle_read_sized,
        "/read-chunks": handle_read_chunks,
        "/read-zero": handle_read_zero,
        "/read-past-eof": handle_read_past_eof,
        "/readline": handle_readline,
        "/readline-sized": handle_readline_sized,
        "/readlines": handle_readlines,
        "/readlines-hint": handle_readlines_hint,
        "/iterate": handle_iterate,
    }

    handler = handlers.get(path)
    if handler is None:
        start_response("404 Not Found", [("Content-Type", "text/plain")])
        return [b"Unknown test path"]

    return handler(environ, start_response)


def _respond(start_response, body):
    payload = body + b";end"
    start_response(
        "200 OK",
        [
            ("Content-Type", "application/octet-stream"),
            ("Content-Length", str(len(payload))),
        ],
    )
    return [payload]


def handle_read_all(environ, start_response):
    content = environ["wsgi.input"].read()
    return _respond(start_response, b"data=" + content)


def handle_read_sized(environ, start_response):
    stream = environ["wsgi.input"]
    first = stream.read(10)
    rest = stream.read()
    return _respond(start_response, b"first=" + first + b",rest=" + rest)


def handle_read_chunks(environ, start_response):
    stream = environ["wsgi.input"]
    chunks = []
    while True:
        chunk = stream.read(7)
        if not chunk:
            break
        chunks.append(chunk)
    body = (
        b"chunks=" + str(len(chunks)).encode()
        + b",data=" + b"".join(chunks)
    )
    return _respond(start_response, body)


def handle_read_zero(environ, start_response):
    stream = environ["wsgi.input"]
    zero = stream.read(0)
    rest = stream.read()
    body = (
        b"zero_len=" + str(len(zero)).encode()
        + b",rest=" + rest
    )
    return _respond(start_response, body)


def handle_read_past_eof(environ, start_response):
    stream = environ["wsgi.input"]
    first = stream.read()
    second = stream.read()
    body = (
        b"first_len=" + str(len(first)).encode()
        + b",second_len=" + str(len(second)).encode()
    )
    return _respond(start_response, body)


def handle_readline(environ, start_response):
    stream = environ["wsgi.input"]
    lines = []
    while True:
        line = stream.readline()
        if not line:
            break
        lines.append(line.rstrip(b"\n"))
    body = (
        b"count=" + str(len(lines)).encode()
        + b",lines=" + b"|".join(lines)
    )
    return _respond(start_response, body)


def handle_readline_sized(environ, start_response):
    stream = environ["wsgi.input"]
    first = stream.readline(5)
    second = stream.readline(5)
    rest = stream.read()
    body = (
        b"first=" + first
        + b",second=" + second
        + b",rest=" + rest
    )
    return _respond(start_response, body)


def handle_readlines(environ, start_response):
    stream = environ["wsgi.input"]
    lines = stream.readlines()
    body = (
        b"count=" + str(len(lines)).encode()
        + b",lines=" + b"|".join(l.rstrip(b"\n") for l in lines)
    )
    return _respond(start_response, body)


def handle_readlines_hint(environ, start_response):
    stream = environ["wsgi.input"]
    lines = stream.readlines(1)
    body = (
        b"count=" + str(len(lines)).encode()
        + b",lines=" + b"|".join(l.rstrip(b"\n") for l in lines)
    )
    return _respond(start_response, body)


def handle_iterate(environ, start_response):
    stream = environ["wsgi.input"]
    lines = [line.rstrip(b"\n") for line in stream]
    body = (
        b"count=" + str(len(lines)).encode()
        + b",lines=" + b"|".join(lines)
    )
    return _respond(start_response, body)
