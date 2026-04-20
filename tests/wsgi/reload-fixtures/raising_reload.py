"""Reload-test fixture: reload_required callback raises.

Exercises the fail-safe branch in wsgi_reload_required: a raising
callback must force a reload rather than silently treating the
module as current.
"""

import time

LOAD_ID = time.time_ns()


def reload_required(resource):
    raise RuntimeError('reload_required callback intentionally raising')


def application(environ, start_response):
    start_response('200 OK', [('Content-Type', 'text/plain')])
    return [str(LOAD_ID).encode()]
