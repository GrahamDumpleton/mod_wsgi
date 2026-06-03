=================================
Delegating File Serving To Apache
=================================

When a WSGI application needs to return the contents of a file, the most
efficient option is almost always to let the web server serve the file
rather than have the application read and yield it itself. With mod_wsgi
this means letting Apache do the work. The :doc:`file-wrapper-extension`
covers one way to do that from within the application. This page covers
the other way, available in daemon mode, where the application hands the
response off to Apache entirely by returning a ``Location`` response
header.

The typical use case is serving a file that the application must first
make an access control decision about. The application performs the
authentication and authorisation, then, instead of streaming the file
back through Python, it tells Apache which local URL should be served in
its place. Apache serves that URL using its own static file handler,
with all the optimisations that brings, including ``sendfile()``, range
requests, conditional requests and correct cache validators.

This is the same mechanism that nginx exposes through the
``X-Accel-Redirect`` header, and it is a built-in, supported alternative
to the third-party ``mod_xsendfile`` module.

How it works
------------

In daemon mode mod_wsgi acts as a gateway in front of the daemon
process, in the same way that ``mod_cgid`` acts as a gateway in front of
a CGI script. As part of that role it honours the CGI specification's
local redirect response (RFC 3875). If the WSGI application returns a
response whose status is ``200`` and which includes a ``Location``
response header whose value is a local URL path, that is, a value
beginning with a ``/`` and with no scheme or host name, then mod_wsgi
does not send the response to the client. Instead it discards any
response content from the application and performs an Apache internal
redirect to the nominated URL. The client receives the response produced
for that URL, and never sees the ``Location`` header or any redirect.

Because the internal redirect is processed by Apache as a fresh request,
the target URL passes through Apache's normal request processing,
including its access control and its static file handler. This is what
makes it possible to let Apache serve a file the application has just
authorised.

The WSGI application
--------------------

The application returns an empty response body, a status of ``200``, and
a ``Location`` header giving the local URL that Apache should serve in
its place::

    def application(environ, start_response):
        # Perform whatever authentication and authorisation checks are
        # required before allowing the file to be served.

        if not user_is_allowed(environ):
            start_response('403 Forbidden', [('Content-Type', 'text/plain')])
            return [b'Forbidden']

        status = '200 OK'
        response_headers = [('Location', '/private/report.pdf')]
        start_response(status, response_headers)

        return []

Note that the value of the ``Location`` header must be a local URL path,
not a file system path. It names a URL that Apache can resolve, and that
URL is what determines which file is ultimately served.

The Apache configuration
------------------------

The private files are mapped to a URL using ``Alias`` (or any other
mechanism that makes them available as a URL), and the directory is made
servable in the usual way::

    Alias /private/ /path/to/app/private/

    <Directory /path/to/app/private/>
        Require all granted
    </Directory>

As written this would also allow a client to request ``/private/`` URLs
directly, bypassing the application's access control. To prevent that,
direct client requests for the private area must be blocked while still
allowing requests that arrive by way of the internal redirect::

    RewriteEngine On

    # Block direct client requests for the private area. THE_REQUEST is
    # the original request line as received from the client and is not
    # changed by mod_wsgi's internal redirect. It therefore only matches
    # a request the client made directly, not one that arrived via a
    # Location response header from the WSGI application.

    RewriteCond %{THE_REQUEST} ^\S+\s/private/
    RewriteRule ^/private/ - [F]

With this in place, a client that asks for ``/private/report.pdf``
directly is refused with a ``403`` response, while a request that the
application redirects to that same URL is served normally.

Why not IS_SUBREQ
-----------------

It is tempting to reach for the ``IS_SUBREQ`` rewrite variable to
distinguish an internally generated request from a direct one, but it is
the wrong tool here. mod_wsgi performs an internal redirect, which Apache
processes as a redirected main request, not as a subrequest.
``IS_SUBREQ`` only reports true for subrequests, so it is false for the
redirected request and cannot be used to gate access to it. Matching
against ``THE_REQUEST`` as shown above is the reliable approach because
that variable always reflects what the client actually sent.

Behaviour and limitations
-------------------------

There are a number of things to be aware of when using this mechanism.

* It is only available in daemon mode. In embedded mode a ``Location``
  header is treated as an ordinary response header.

* The response status must be ``200`` for the internal redirect to be
  triggered. A status such as ``302`` is treated as a normal client
  redirect and is sent to the client as is.

* The ``Location`` value must be a local URL path. If it is an absolute
  URL, with a scheme and host name, mod_wsgi passes the response through
  unchanged rather than redirecting. This differs from the CGI
  specification, where an absolute ``Location`` with a ``200`` status is
  turned into a client redirect; mod_wsgi does not do that, on the basis
  that a WSGI application that wants a client redirect sets the status
  itself.

* The internal redirect is always performed as a ``GET`` request,
  regardless of the method of the original request, and any request
  content already read is not made available to it. The target URL is
  therefore expected to be a resource that can be served by a ``GET``.

* Because the target URL is processed as a normal request, Apache's
  access control applies to it. This is why the private area must be
  protected as shown above; making it servable by Apache also makes it
  reachable by clients unless direct access is explicitly blocked.

Relationship to the file wrapper extension
------------------------------------------

This mechanism and the :doc:`file-wrapper-extension` solve the same
underlying problem, returning file contents efficiently, but in
different ways and with different trade-offs.

The file wrapper extension keeps the application in control of which file
is returned and works in both embedded and daemon mode, but the file
contents still pass from the application to Apache, and any WSGI
middleware in the stack can defeat the optimisation by consuming or
wrapping the response.

Delegating to Apache with a ``Location`` header hands the work to Apache
completely, so the file contents never pass through Python at all and no
middleware can interfere with how they are served. The cost is that it is
daemon mode only and that the file must be reachable as a URL within the
Apache configuration, which in turn must be protected against direct
access as described above.
