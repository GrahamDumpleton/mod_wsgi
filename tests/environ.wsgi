from __future__ import print_function

import os
import sys

try:
    from cStringIO import StringIO
except ImportError:
    from io import StringIO

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
