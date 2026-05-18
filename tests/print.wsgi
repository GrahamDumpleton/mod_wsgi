import sys

# Module-scope prints. These run once per interpreter at import time,
# outside any request. mod_wsgi routes sys.stdout/sys.stderr at this
# scope to the Apache error log, so each of the four lines below
# appears at level error tagged [wsgi:error] but WITHOUT a
# [remote ...] or [script ...] decoration (there is no active
# request).
#
# The queued no-newline fragment is buffered until a subsequent
# newline-terminated print closes the line; without that follow-up
# print, the fragment would never surface in the log because nothing
# at module scope flushes a partial line.

print('module-scope print() to default (sys.stdout)')
print('module-scope print() to sys.stdout', file=sys.stdout)
print('module-scope print() to sys.stderr', file=sys.stderr)
print('module-scope queued no-newline', end='')
print('module-scope queued flushed by newline')

def application(environ, start_response):
    # Request-scope prints. For the duration of the request mod_wsgi
    # replaces sys.stdout and sys.stderr with the wsgi.errors stream,
    # so all four destinations below converge on the same target and
    # log lines pick up the request-scope [remote ...] / [script ...]
    # decoration applied by mod_wsgi when writing through wsgi.errors.
    #
    # Each newline-terminated print() surfaces as its own log line.

    print('request print() to default (sys.stdout)')
    print('request print() to sys.stdout', file=sys.stdout)
    print('request print() to sys.stderr', file=sys.stderr)
    print('request print() to wsgi.errors', file=environ['wsgi.errors'])

    # Two queued no-newline fragments stack into the same buffered
    # line. The bare print() writes a newline which terminates the
    # buffered fragment so it surfaces immediately rather than
    # waiting on any later flush.

    print('request queued no-newline', end='')
    print('request queued with-sep', '+', sep='', end='')
    print()

    # Explicit .flush() on each request-scope stream emits whatever
    # has accumulated on that stream as its own log line, even if
    # the buffered fragment does not itself end in a newline. The
    # log line is still cleanly terminated because mod_wsgi hands
    # the buffered bytes to Apache's ap_log_rerror, which appends a
    # newline to every emitted record.

    print('request flush() via sys.stdout', end='')
    sys.stdout.flush()
    print('request flush() via sys.stderr', end='', file=sys.stderr)
    sys.stderr.flush()
    print('request flush() via wsgi.errors', end='',
            file=environ['wsgi.errors'])
    environ['wsgi.errors'].flush()

    # A final unterminated fragment with no explicit flush. At
    # request completion mod_wsgi auto-flushes any buffered line
    # fragment on the request's stream, so this still surfaces in
    # the log rather than being lost.

    print('request queued auto-flushed at request end', end='')

    status = '200 OK'
    output = b'Hello World!'

    response_headers = [('Content-type', 'text/plain'),
                        ('Content-Length', str(len(output)))]
    start_response(status, response_headers)

    return [output]
