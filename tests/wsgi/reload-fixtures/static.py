"""Reload-test fixture: no reload_required callback.

Exercises the baseline mtime-only reload path. The test harness
either leaves the file alone (expect no reload) or touches it
between requests (expect reload).
"""

import time

LOAD_ID = time.time_ns()


def application(environ, start_response):
    start_response('200 OK', [('Content-Type', 'text/plain')])
    return [str(LOAD_ID).encode()]
