import os
import sys
import locale

from io import StringIO

import mod_wsgi
import apache


def application(environ, start_response):
    headers = [("Content-Type", 'text/plain; charset="UTF-8"')]
    write = start_response("200 OK", headers)

    input = environ["wsgi.input"]
    output = StringIO()

    if os.name != "nt":
        print(f"PID: {os.getpid()}", file=output)
        print(f"UID: {os.getuid()}", file=output)
        print(f"GID: {os.getgid()}", file=output)
        print(f"CWD: {os.getcwd()}", file=output)
        print(file=output)

    print(f"STDOUT: {sys.stdout.name}", file=output)
    print(f"STDERR: {sys.stderr.name}", file=output)
    print(f'ERRORS: {environ["wsgi.errors"].name}', file=output)
    print(file=output)

    print(f"python.version: {sys.version!r}", file=output)
    print(f"python.prefix: {sys.prefix!r}", file=output)
    print(f"python.path: {sys.path!r}", file=output)
    print(file=output)

    print(f"apache.version: {apache.version!r}", file=output)
    print(f"mod_wsgi.version: {mod_wsgi.version!r}", file=output)
    print(file=output)

    print(f"mod_wsgi.process_group: {mod_wsgi.process_group}", file=output)
    print(f"mod_wsgi.application_group: {mod_wsgi.application_group}", file=output)
    print(file=output)

    print(f"mod_wsgi.maximum_processes: {mod_wsgi.maximum_processes}", file=output)
    print(f"mod_wsgi.threads_per_process: {mod_wsgi.threads_per_process}", file=output)
    print(file=output)

    print(f"apache.description: {apache.description}", file=output)
    print(f"apache.build_date: {apache.build_date}", file=output)
    print(f"apache.mpm_name: {apache.mpm_name}", file=output)
    print(f"apache.maximum_processes: {apache.maximum_processes}", file=output)
    print(f"apache.threads_per_process: {apache.threads_per_process}", file=output)
    print(file=output)

    print(f'PATH: {os.environ.get("PATH")}', file=output)
    print(file=output)

    print(f'LANG: {os.environ.get("LANG")}', file=output)
    print(f'LC_ALL: {os.environ.get("LC_ALL")}', file=output)
    print(f"sys.getdefaultencoding(): {sys.getdefaultencoding()}", file=output)
    print(f"sys.getfilesystemencoding(): {sys.getfilesystemencoding()}", file=output)
    print(f"locale.getlocale(): {locale.getlocale()}", file=output)
    print(f"locale.getdefaultlocale(): {locale.getdefaultlocale()}", file=output)
    print(
        f"locale.getpreferredencoding(): {locale.getpreferredencoding()}", file=output
    )
    print(file=output)

    for key in sorted(environ):
        print(f"{key}: {environ[key]!r}", file=output)
    print(file=output)

    for key in sorted(os.environ):
        print(f"{key}: {os.environ[key]!r}", file=output)
    print(file=output)

    yield output.getvalue().encode("UTF-8")

    block_size = 8192

    data = input.read(block_size)
    while data:
        yield data
        data = input.read(block_size)
