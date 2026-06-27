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
    # Tests that need a daemon group with non-default options (e.g.
    # short request-timeout / interrupt-timeout for the
    # interrupt_timeout test) declare it in their per-test .conf as a
    # named WSGIDaemonProcess and dispatch to it here. The named group
    # must exist in the harness config or routing fails.
    if environ.get("SCRIPT_NAME", "").startswith("/test/wsgi/interrupt-timeout"):
        return "interrupt-timeout-test"

    # The request_body test's /no-handshake mount routes to a dedicated
    # daemon group whose queue-timeout is 0 (see request_body.conf).
    # Combined with WSGIScriptReloading Off on that mount this disables
    # the deferred-content handshake, exercising the daemon frame-read
    # path that must not over-read the proxied request body.
    if environ.get("SCRIPT_NAME", "").startswith(
        "/test/wsgi/request-body/no-handshake"
    ):
        return "request-body-no-handshake"

    # Matches "process-group=localhost:$PORT" on the WSGIScriptAlias.
    # The harness passes MOD_WSGI_TESTS_DAEMON_PORT via SetEnv so
    # requests arriving on the HTTPS listener (where SERVER_PORT is
    # the HTTPS port) still route to the single daemon bound to the
    # primary HTTP port. Falls back to SERVER_PORT when unset.
    port = environ.get("MOD_WSGI_TESTS_DAEMON_PORT") or environ["SERVER_PORT"]
    return "localhost:" + port


def application_group(environ):
    # Tests that need a named sub-interpreter (rather than the
    # daemon's main interpreter) declare a path-prefix here. Without
    # this override the static "%{GLOBAL}" on every WSGIScriptAlias
    # would route the request to the main interpreter instead.
    if environ.get("SCRIPT_NAME", "").startswith("/test/wsgi/sub-interpreter"):
        return "test-subinterp"

    # Empty string resolves to the same application group as the
    # "%{GLOBAL}" placeholder used in the WSGIScriptAlias.
    return ""


def callable_object(environ):
    # Default WSGI callable name used by every test app.
    return "application"
