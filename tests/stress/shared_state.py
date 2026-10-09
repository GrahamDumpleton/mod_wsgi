"""
Stress test application which reports when per-thread state is shared.

Each request records the native thread id against the mod_wsgi thread
id it was given and against the address of the Python thread state it
is running on. A later request which sees either of them from a
different native thread writes a line starting with ``STRESS shared``
to stderr, which Apache collects into the error log, and the stress
runner counts those lines. Each pairing is reported once per process.

The request sleeps briefly so that a burst of requests keeps every
thread of the process busy at the same time.
"""

import ctypes
import os
import threading
import time

_PyThreadState_Get = ctypes.pythonapi.PyThreadState_Get
_PyThreadState_Get.restype = ctypes.c_void_p

_lock = threading.Lock()
_owners = {}
_reported = set()


def _check(kind, key, native_id):
    with _lock:
        owner = _owners.setdefault((kind, key), native_id)
        if owner == native_id or (kind, key, native_id) in _reported:
            return
        _reported.add((kind, key, native_id))

    os.write(2, ('STRESS shared %s %s used by native threads %d and %d '
                 'in process %d\n' % (kind, key, owner, native_id,
                 os.getpid())).encode())


def application(environ, start_response):
    native_id = threading.get_native_id()

    _check('thread_id', environ['mod_wsgi.thread_id'], native_id)
    _check('thread_state', '%#x' % _PyThreadState_Get(), native_id)

    time.sleep(0.02)

    start_response('200 OK', [('Content-Type', 'text/plain')])
    return [b'ok\n']
