import warnings

# Probe the Python warnings filter chain as configured by Apache.
# No simplefilter / filterwarnings call is made here, so the only
# things shaping the chain are Python's defaults and any
# WSGIPythonWarnings directives (or --python-warnings options on
# mod_wsgi-express, which emit the same directive).
#
# Whether each warnings.warn() call below fires depends entirely
# on that combined chain:
#
# - No --python-warnings: UserWarning fires (default action for a
#   first occurrence), DeprecationWarning is suppressed (Python's
#   default filter ignores DeprecationWarning outside __main__).
# - --python-warnings always: both fire.
# - --python-warnings 'ignore::UserWarning': UserWarning suppressed,
#   DeprecationWarning still default-suppressed.
# - --python-warnings error: the first warnings.warn() below raises
#   and module import fails (Apache logs the import error).
#
# Output goes via warnings.showwarning() directly to sys.stderr
# (which mod_wsgi aliases to wsgi.errors), so log lines do not
# carry the WARNING py.warnings prefix that logging.wsgi's
# captureWarnings(True) demo produces.

warnings.warn('module-scope UserWarning', UserWarning)
warnings.warn('module-scope DeprecationWarning', DeprecationWarning)

def application(environ, start_response):
    warnings.warn('request UserWarning', UserWarning)
    warnings.warn('request DeprecationWarning', DeprecationWarning)

    status = '200 OK'
    output = b'Hello World!'

    response_headers = [('Content-type', 'text/plain'),
                        ('Content-Length', str(len(output)))]
    start_response(status, response_headers)

    return [output]
