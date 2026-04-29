==================
WSGIDispatchScript
==================

:Description: Run a Python script per request to override routing decisions.
:Syntax: ``WSGIDispatchScript`` *path* ``[`` *options* ``]``
:Context: server config, virtual host, directory, .htaccess
:Override: ``FileInfo``

Specifies a Python script that mod_wsgi runs early in the request
pipeline so it can override the daemon process group, the application
group, or the callable name that the request would otherwise be
dispatched to. This allows routing decisions to depend on attributes
of the live request (URL, headers, Apache environment variables) that
aren't available when the static configuration is written.

The dispatch script may define any of the following module-level
callables. Each, if present, receives the WSGI ``environ`` for the
incoming request and returns a string. The string is interpreted using
the same expansion rules as the corresponding directive
(``%{GLOBAL}``, ``%{ENV:variable}``, etc.). Returning ``None`` from a
callable leaves the existing decision in place.

* **process_group(environ)** — overrides which daemon process group
  the request will be dispatched to. Equivalent of the
  ``WSGIProcessGroup`` directive or the ``process-group`` option to
  ``WSGIScriptAlias``.
* **application_group(environ)** — overrides which application
  group (Python sub interpreter) the WSGI application runs in.
  Equivalent of ``WSGIApplicationGroup``.
* **callable_object(environ)** — overrides the name of the callable
  in the WSGI script file that is treated as the WSGI entry point.
  Equivalent of ``WSGICallableObject``.

Options which can be supplied to the directive are:

**application-group=name**
    Application group in which the dispatch script itself is
    loaded and executed. If not supplied, the dispatch script
    runs in the application group of the request being
    dispatched.

For example, to route requests to one of three daemon process
groups based on the URL prefix::

  WSGIDaemonProcess admin processes=2 threads=15
  WSGIDaemonProcess api processes=4 threads=15
  WSGIDaemonProcess web processes=4 threads=15

  WSGIDispatchScript /etc/apache2/wsgi/dispatch.py

with ``dispatch.py``::

  def process_group(environ):
      path = environ.get("REQUEST_URI", "")
      if path.startswith("/admin/"):
          return "admin"
      if path.startswith("/api/"):
          return "api"
      return "web"

The dispatch script itself is loaded in an Apache child process, not
in the daemon process group — it runs in embedded mode. Script
reloading applies to dispatch scripts: if the file's modification time
changes, the script is re-imported on the next request that needs it.

The directive only sets up the dispatch script; it does not by itself
designate the request as a WSGI application. The actual WSGI
application is still mounted via ``WSGIScriptAlias``, ``SetHandler
wsgi-script``, or similar. The dispatch script's role is to override
the routing decisions for that mount.
