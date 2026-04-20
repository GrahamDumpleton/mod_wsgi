"""Reload-test fixture: strip __mtime__ per request.

mod_wsgi stamps __mtime__ on the module via PyModule_AddObject
AFTER PyImport_ExecCodeModuleEx returns, so a module-scope del
cannot see the attribute. The handler strips it on every request
instead. The next request's reload check hits the "no __mtime__"
branch and forces a reload.
"""

import sys
import time

LOAD_ID = time.time_ns()


def application(environ, start_response):
    sys.modules[__name__].__dict__.pop('__mtime__', None)

    start_response('200 OK', [('Content-Type', 'text/plain')])
    return [str(LOAD_ID).encode()]
