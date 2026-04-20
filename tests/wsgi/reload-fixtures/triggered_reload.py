"""Reload-test fixture: reload_required callback is one-shot via a flag file.

If the flag file at TRIGGER_PATH exists, the callback removes it and
returns True (reload required). Otherwise it returns False. The flag
has to survive daemon-process restart (a "True" return in daemon
mode triggers a restart), so it lives on disk rather than in module
scope.

The test harness creates the flag between two requests to observe
one reload. A callback that kept returning True would produce an
infinite restart loop in daemon mode, which is why this fixture is
one-shot rather than always-True.
"""

import os
import time

LOAD_ID = time.time_ns()
TRIGGER_PATH = '/tmp/mod_wsgi_reload_test_triggered'


def reload_required(resource):
    if os.path.exists(TRIGGER_PATH):
        try:
            os.unlink(TRIGGER_PATH)
        except FileNotFoundError:
            pass
        return True
    return False


def application(environ, start_response):
    start_response('200 OK', [('Content-Type', 'text/plain')])
    return [str(LOAD_ID).encode()]
