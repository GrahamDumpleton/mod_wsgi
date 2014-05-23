from __future__ import print_function

import os
import sys

try:
    from cStringIO import StringIO
except ImportError:
    from io import StringIO

import mod_wsgi
import apache

def application(environ, start_response):
    headers = []
    headers.append(('Content-Type', 'text/plain'))
    write = start_response('200 OK', headers)

    input = environ['wsgi.input']
    output = StringIO()

    print('PID: %s' % os.getpid(), file=output)
    print('UID: %s' % os.getuid(), file=output)
    print('GID: %s' % os.getgid(), file=output)
    print(file=output)

    print('mod_wsgi.process_group: %s' % mod_wsgi.process_group,
            file=output)
    print('mod_wsgi.application_group: %s' % mod_wsgi.application_group,
            file=output)
    print(file=output)

    print('mod_wsgi.maximum_processes: %s' % mod_wsgi.maximum_processes,
            file=output)
    print('mod_wsgi.threads_per_process: %s' % mod_wsgi.threads_per_process,
            file=output)
    print(file=output)

    print('apache.mpm_name: %s' % apache.mpm_name, file=output)
    print('apache.maximum_processes: %s' % apache.maximum_processes,
            file=output)
    print('apache.threads_per_process: %s' % apache.threads_per_process,
            file=output)
    print(file=output)

    print('PATH: %s' % sys.path, file=output)
    print(file=output)

    keys = sorted(environ.keys())
    for key in keys:
        print('%s: %s' % (key, repr(environ[key])), file=output)
    print(file=output)

    keys = sorted(os.environ.keys())
    for key in keys:
        print('%s: %s' % (key, repr(os.environ[key])), file=output)
    print(file=output)

    result = output.getvalue()

    if not isinstance(result, bytes):
        result = result.encode('UTF-8')

    yield result

    yield input.read(int(environ.get('CONTENT_LENGTH', '0')))
