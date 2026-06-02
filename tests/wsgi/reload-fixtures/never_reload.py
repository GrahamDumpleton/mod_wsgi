"""Reload-test fixture: reload_required callback always returns False.

Reload check must defer to the callback and skip the reload. The
module stays cached across requests (same LOAD_ID).
"""

import time

LOAD_ID = time.time_ns()


def reload_required(resource):
    return False


def application(environ, start_response):
    start_response('200 OK', [('Content-Type', 'text/plain')])
    return [str(LOAD_ID).encode()]
