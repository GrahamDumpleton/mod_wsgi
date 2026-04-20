"""Primary mount for the reload test.

The harness pairs tests/wsgi/reload.sh with tests/wsgi/reload.py
and mounts this file at /test/wsgi/reload. The real fixtures for
each reload scenario live under tests/wsgi/reload-fixtures/ and
are mounted via tests/wsgi/reload.conf.
"""


def application(environ, start_response):
    start_response('200 OK', [('Content-Type', 'text/plain')])
    return [b'see /test/wsgi/reload/<fixture>']
