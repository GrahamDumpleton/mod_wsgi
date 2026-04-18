"""Test-wide WSGI dispatch script.

Loaded by scripts/run-tests.sh via a server-level WSGIDispatchScript
directive so every request exercises the dispatch code path. The
returned process group, application group, and callable name mirror
the static ``process-group=localhost:$PORT application-group=%{GLOBAL}``
options on the per-test WSGIScriptAlias directives, so routing is
unchanged and all existing tests continue to execute in the same
daemon process against the same callable name.
"""


def process_group(environ):
    # Matches "process-group=localhost:$PORT" on the WSGIScriptAlias.
    # SERVER_PORT is surfaced by Apache in the dispatch environ.
    return "localhost:" + environ["SERVER_PORT"]


def application_group(environ):
    # Empty string resolves to the same application group as the
    # "%{GLOBAL}" placeholder used in the WSGIScriptAlias.
    return ""


def callable_object(environ):
    # Default WSGI callable name used by every test app.
    return "application"
