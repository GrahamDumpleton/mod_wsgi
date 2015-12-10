from __future__ import print_function

import os
import sys
import locale

try:
    from cStringIO import StringIO
except ImportError:
    from io import StringIO

import mod_wsgi
import apache

def application(environ, start_response):
    headers = []
    headers.append(('Content-Type', 'text/plain; charset="UTF-8"'))
    write = start_response('200 OK', headers)

    input = environ['wsgi.input']
    output = StringIO()

    print('PID: %s' % os.getpid(), file=output)
    print('UID: %s' % os.getuid(), file=output)
    print('GID: %s' % os.getgid(), file=output)
    print('CWD: %s' % os.getcwd(), file=output)
    print(file=output)

    print('python.version: %r' % (sys.version,), file=output)
    print('python.prefix: %r' % (sys.prefix,), file=output)
    print('python.path: %r' % (sys.path,), file=output)
    print(file=output)

    print('apache.version: %r' % (apache.version,), file=output)
    print('mod_wsgi.version: %r' % (mod_wsgi.version,), file=output)
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
    print('mod_wsgi.process_metrics: %s' % mod_wsgi.process_metrics(),
            file=output)
    print('mod_wsgi.server_metrics: %s' % mod_wsgi.server_metrics(),
            file=output)
    print(file=output)

    metrics = mod_wsgi.server_metrics()

    if metrics:
        for process in metrics['processes']:
           for worker in process['workers']:
               print(worker['status'], file=output, end='')
        print(file=output)
        print(file=output)

    print('apache.description: %s' % apache.description, file=output)
    print('apache.build_date: %s' % apache.build_date, file=output)
    print('apache.mpm_name: %s' % apache.mpm_name, file=output)
    print('apache.maximum_processes: %s' % apache.maximum_processes,
            file=output)
    print('apache.threads_per_process: %s' % apache.threads_per_process,
            file=output)
    print(file=output)

    print('PATH: %s' % sys.path, file=output)
    print(file=output)

    print('LANG: %s' % os.environ.get('LANG'), file=output)
    print('LC_ALL: %s' % os.environ.get('LC_ALL'), file=output)
    print('sys.getdefaultencoding(): %s' % sys.getdefaultencoding(),
            file=output)
    print('sys.getfilesystemencoding(): %s' % sys.getfilesystemencoding(),
            file=output)
    print('locale.getlocale(): %s' % (locale.getlocale(),),
            file=output)
    print('locale.getdefaultlocale(): %s' % (locale.getdefaultlocale(),),
            file=output)
    print('locale.getpreferredencoding(): %s' % locale.getpreferredencoding(),
            file=output)
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

    block_size = 8192

    data = input.read(block_size)
    while data:
        yield data
        data = input.read(block_size)
