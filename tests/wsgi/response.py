"""Test WSGI response iteration behaviour in Adapter_run.

Covers:

  * plain list / tuple / generator returns
  * empty list and empty generator
  * close() call on a custom iterable after normal iteration
  * try/finally running on a generator when iteration completes
  * close() sending GeneratorExit into a paused generator when
    adapter bails out mid-stream, triggering the finally block
  * exceptions raised before first yield (500 response)
  * exceptions raised after a yield (200, truncated response)
  * try/finally running on a generator that raises after yielding
  * non-bytes item on first iteration (500)
  * non-bytes item after first yield (200, truncated)
  * exact-size Content-Length passes through
  * over-delivery is truncated at declared Content-Length
  * streaming many small chunks
"""


def application(environ, start_response):
    path = environ.get("PATH_INFO", "/")

    handlers = {
        "/list": handle_list,
        "/tuple": handle_tuple,
        "/generator": handle_generator,
        "/empty-list": handle_empty_list,
        "/empty-generator": handle_empty_generator,
        "/iterable-with-close": handle_iterable_with_close,
        "/generator-finally": handle_generator_finally,
        "/close-via-generator-exit": handle_close_via_generator_exit,
        "/raise-first": handle_raise_first,
        "/raise-midway": handle_raise_midway,
        "/raise-with-finally": handle_raise_with_finally,
        "/raise-systemexit": handle_raise_systemexit,
        "/raise-request-timeout": handle_raise_request_timeout,
        "/non-bytes-first": handle_non_bytes_first,
        "/non-bytes-midway": handle_non_bytes_midway,
        "/content-length-exact": handle_content_length_exact,
        "/content-length-over": handle_content_length_over,
        "/many-chunks": handle_many_chunks,
    }

    handler = handlers.get(path)
    if handler is None:
        start_response("404 Not Found", [("Content-Type", "text/plain")])
        return [b"Unknown test path"]

    return handler(environ, start_response)


def handle_list(environ, start_response):
    start_response("200 OK", [("Content-Type", "text/plain")])
    return [b"chunk1-", b"chunk2-", b"chunk3"]


def handle_tuple(environ, start_response):
    start_response("200 OK", [("Content-Type", "text/plain")])
    return (b"tuple-a", b"tuple-b")


def handle_generator(environ, start_response):
    start_response("200 OK", [("Content-Type", "text/plain")])

    def gen():
        yield b"gen-one-"
        yield b"gen-two-"
        yield b"gen-three"

    return gen()


def handle_empty_list(environ, start_response):
    start_response("200 OK", [("Content-Type", "text/plain")])
    return []


def handle_empty_generator(environ, start_response):
    start_response("200 OK", [("Content-Type", "text/plain")])

    def gen():
        return
        yield  # pragma: no cover - makes this a generator function

    return gen()


def handle_iterable_with_close(environ, start_response):
    errors = environ["wsgi.errors"]

    class MyIter:
        def __init__(self):
            self.items = [b"iter-a-", b"iter-b"]
            self.i = 0

        def __iter__(self):
            return self

        def __next__(self):
            if self.i >= len(self.items):
                raise StopIteration
            item = self.items[self.i]
            self.i += 1
            return item

        def close(self):
            errors.write("MARKER_ITER_CLOSE_77777\n")

    start_response("200 OK", [("Content-Type", "text/plain")])
    return MyIter()


def handle_generator_finally(environ, start_response):
    errors = environ["wsgi.errors"]

    def gen():
        try:
            yield b"gen-fin-a-"
            yield b"gen-fin-b"
        finally:
            errors.write("MARKER_GEN_FINALLY_77777\n")

    start_response("200 OK", [("Content-Type", "text/plain")])
    return gen()


def handle_close_via_generator_exit(environ, start_response):
    errors = environ["wsgi.errors"]

    def gen():
        try:
            yield b"first-ok"
            # Non-bytes item makes the adapter break out of its
            # iteration loop with a TypeError, leaving the generator
            # paused at this yield. close() then sends GeneratorExit
            # into the yield, which should unwind through the
            # try/finally.
            yield 12345
            yield b"never-reached"
        finally:
            errors.write("MARKER_CLOSE_GEXIT_77777\n")

    start_response("200 OK", [("Content-Type", "text/plain")])
    return gen()


def handle_raise_first(environ, start_response):
    def gen():
        raise RuntimeError("raise-first-boom")
        yield b""  # pragma: no cover

    start_response("200 OK", [("Content-Type", "text/plain")])
    return gen()


def handle_raise_midway(environ, start_response):
    def gen():
        yield b"before-boom"
        raise RuntimeError("raise-midway-boom")

    start_response("200 OK", [("Content-Type", "text/plain")])
    return gen()


def handle_raise_with_finally(environ, start_response):
    errors = environ["wsgi.errors"]

    def gen():
        try:
            yield b"before-fin-err"
            raise RuntimeError("raise-after-yield")
        finally:
            errors.write("MARKER_RAISE_FINALLY_77777\n")

    start_response("200 OK", [("Content-Type", "text/plain")])
    return gen()


def handle_raise_systemexit(environ, start_response):
    raise SystemExit("raise-systemexit-msg")


def handle_raise_request_timeout(environ, start_response):
    import mod_wsgi
    raise mod_wsgi.RequestTimeout("raise-request-timeout-msg")


def handle_non_bytes_first(environ, start_response):
    start_response("200 OK", [("Content-Type", "text/plain")])
    return ["not-bytes-str"]


def handle_non_bytes_midway(environ, start_response):
    start_response("200 OK", [("Content-Type", "text/plain")])
    return [b"bytes-ok", 12345]


def handle_content_length_exact(environ, start_response):
    content = b"exactly10!"
    start_response("200 OK", [
        ("Content-Type", "text/plain"),
        ("Content-Length", str(len(content))),
    ])
    return [content]


def handle_content_length_over(environ, start_response):
    start_response("200 OK", [
        ("Content-Type", "text/plain"),
        ("Content-Length", "5"),
    ])
    return [b"this-is-longer-than-five"]


def handle_many_chunks(environ, start_response):
    start_response("200 OK", [("Content-Type", "text/plain")])

    def gen():
        for i in range(100):
            yield b"chunk%03d-" % i

    return gen()
