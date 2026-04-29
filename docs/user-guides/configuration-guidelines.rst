========================
Configuration Guidelines
========================

This document is a topical reference for the Apache configuration
needed to host WSGI applications with mod_wsgi. It covers the
mounting directives, static-file co-hosting, the daemon-mode process
model, application groups, per-application configuration injection,
authentication, request-body limits, and reverse-proxy/HTTPS
deployment.

For a step-by-step first-time tutorial — three progressively richer
``VirtualHost`` examples building up from basic mounting to daemon
mode — see :doc:`quick-configuration-guide` instead.

If you do not need to integrate with an existing system Apache
install, the ``mod_wsgi-express`` command (installed alongside the
``mod_wsgi`` PyPI package) generates a working configuration in the
same shape as the examples on this page and runs Apache directly.
See :doc:`../getting-started` for that path. This page is for cases
where you are hand-writing Apache configuration so a system Apache
instance you already operate can host the WSGI application.

The WSGIScriptAlias Directive
-----------------------------

Configuring Apache to run WSGI applications using mod_wsgi is similar
to how Apache is configured to run CGI applications. To streamline
this, mod_wsgi provides a ``WSGIScriptAlias`` directive analogous to
Apache's ``ScriptAlias``: it combines the URL-to-file mapping and the
handler designation into a single directive.

The first form of ``WSGIScriptAlias`` associates a WSGI application
with a specific URL prefix::

    WSGIScriptAlias /myapp /usr/local/wsgi/scripts/myapp.wsgi

The second argument must be the absolute pathname of the WSGI script
file. A trailing slash should not be added when the path refers to a
script file rather than a directory.

The script file must define a callable named ``application`` that
follows the WSGI specification. A minimal hello-world example::

    def application(environ, start_response):
        status = '200 OK'
        output = b'Hello World!'

        response_headers = [('Content-type', 'text/plain'),
                            ('Content-Length', str(len(output)))]
        start_response(status, response_headers)

        return [output]

The callable name is fixed unless you override it via
:doc:`../configuration-directives/WSGICallableObject`. The script file
does not need to use a ``.py`` extension. The ``.wsgi`` convention
shown in the examples on this page is used to avoid clashing with any
pre-existing ``AddHandler`` directive that may already map ``.py``
files to a different handler such as ``cgi-script``. If you know
there is no such conflict, the script file can use ``.py`` like any
other Python file.

Apache access controls apply to the directory containing the WSGI
script. If the script lives outside any directory already known to
Apache, declare it with a ``<Directory>`` block::

    <Directory /usr/local/wsgi/scripts>
        Require all granted
    </Directory>

Apply ``Require`` to ``<Directory>`` rather than ``<Location>`` —
applying access controls to a ``<Location>`` (especially ``/``) is
not best practice and can weaken the security of the server.

Use of ``WSGIScriptAlias`` does not require explicitly enabling
``ExecCGI`` via ``Options`` — execute permission is implied by the
directive itself, just as for ``ScriptAlias``.

To mount a WSGI application at the root of the site::

    WSGIScriptAlias / /usr/local/wsgi/scripts/myapp.wsgi

Multiple ``WSGIScriptAlias`` directives can be listed; earlier
matches take precedence. List the most specific URL prefixes first::

    WSGIScriptAlias /wiki /usr/local/wsgi/scripts/mywiki.wsgi
    WSGIScriptAlias /blog /usr/local/wsgi/scripts/myblog.wsgi
    WSGIScriptAlias / /usr/local/wsgi/scripts/myapp.wsgi

The second form maps a URL prefix to a directory of WSGI scripts.
The next path segment after the prefix selects which script in the
target directory handles the request::

    WSGIScriptAlias /wsgi/ /usr/local/wsgi/scripts/

Both the URL prefix and directory path must end with a trailing
slash in this form.

To allow scripts to be selected without their extension appearing
in the URL, use ``WSGIScriptAliasMatch`` with a regex that captures
the script name and substitutes it back into the file path::

    WSGIScriptAliasMatch ^/wsgi/([^/]+) /usr/local/wsgi/scripts/$1.wsgi

Framework integration
~~~~~~~~~~~~~~~~~~~~~

For most Python web frameworks the WSGI script file is something
the framework already provides:

* **Django.** ``django-admin startproject`` generates a ``wsgi.py``
  at the top of the project tree that exposes a WSGI ``application``
  callable. Point ``WSGIScriptAlias`` at that file directly::

      WSGIScriptAlias / /var/www/myproject/myproject/wsgi.py

* **Flask.** Either create a small ``.wsgi`` script that imports
  the Flask application instance and binds it to ``application``::

      from myapp import app as application

  Then point ``WSGIScriptAlias`` at the ``.wsgi`` file. Or, point
  ``WSGIScriptAlias`` directly at the Flask module and use
  :doc:`../configuration-directives/WSGICallableObject` to tell
  mod_wsgi the callable is named ``app`` rather than
  ``application``::

      WSGIScriptAlias / /var/www/myapp/myapp.py

      <Directory /var/www/myapp>
          <Files myapp.py>
              WSGICallableObject app
          </Files>
          Require all granted
      </Directory>

  This avoids the extra shim file at the cost of having
  ``WSGIScriptAlias`` point at a ``.py`` file — only do this if no
  ``AddHandler`` directive in scope already maps ``.py`` to a
  different handler.

* **Other WSGI frameworks.** Whatever the framework's documented
  WSGI entry-point object is, expose it as a top-level
  ``application`` symbol in the script file pointed at by
  ``WSGIScriptAlias``.

ASGI frameworks such as FastAPI and Starlette do not natively run
on a WSGI server. They can be hosted under mod_wsgi via an
ASGI-to-WSGI shim such as ``a2wsgi``, but the async benefits are
lost in that configuration. The recommended pattern for ASGI
applications is to run them under a dedicated ASGI server
(``uvicorn``, ``hypercorn``) — optionally with Apache acting as a
reverse proxy in front, terminating TLS and serving static files.

Hosting Of Static Files
-----------------------

When ``WSGIScriptAlias`` mounts an application at the root of the
site, every request maps to the WSGI application — including
requests for static assets that the application does not own. Use
``Alias``, ``AliasMatch``, or directory-based handler configuration
to route those requests back to Apache before the WSGI alias
matches::

    Alias /robots.txt /usr/local/wsgi/static/robots.txt
    Alias /favicon.ico /usr/local/wsgi/static/favicon.ico

    AliasMatch /([^/]*\.css) /usr/local/wsgi/static/styles/$1

    Alias /media/ /usr/local/wsgi/static/media/

    <Directory /usr/local/wsgi/static>
        Require all granted
    </Directory>

    WSGIScriptAlias / /usr/local/wsgi/scripts/myapp.wsgi

    <Directory /usr/local/wsgi/scripts>
        Require all granted
    </Directory>

List the more specific URLs first. In practice the ``Alias``
directive takes precedence over ``WSGIScriptAlias`` regardless of
order, but explicit ordering is good practice and makes the
intent obvious to a future reader.

Defining Process Groups
-----------------------

mod_wsgi can run a WSGI application in either *embedded* mode or
*daemon* mode.

In embedded mode the application runs in Python sub-interpreters
hosted inside the Apache child processes themselves. This gives the
lowest per-request overhead but has substantial drawbacks: every
code change requires a full Apache restart to pick up; the Apache
child processes' memory footprint grows with the application; the
default Apache MPM tuning is geared for serving static files and
PHP and is rarely a good fit for a Python web application; and the
application shares its process with other Apache modules including
``mod_php`` and any other dynamic-content modules in use.

In daemon mode mod_wsgi creates a dedicated set of processes
running just the WSGI application. The Apache child processes act
as proxies, forwarding requests to the daemon processes and relaying
responses back. Daemon processes can be configured independently of
Apache MPM tuning, can run as a different user from Apache, can be
restarted without restarting Apache itself (touch the WSGI script
file), and isolate the application from other Apache modules.

**Daemon mode is the recommended deployment pattern for production
WSGI applications.** The remainder of this section assumes daemon
mode.

A daemon process group is declared with ``WSGIDaemonProcess``. WSGI
applications are delegated to a process group with
``WSGIProcessGroup``. A complete virtual host hosting a single WSGI
application in daemon mode, with static files served by Apache::

    <VirtualHost *:80>
        ServerName www.example.com

        WSGIDaemonProcess myapp processes=2 threads=15 \
            display-name=%{GROUP}
        WSGIProcessGroup myapp

        Alias /favicon.ico /usr/local/wsgi/static/favicon.ico
        AliasMatch /([^/]*\.css) /usr/local/wsgi/static/styles/$1
        Alias /media/ /usr/local/wsgi/static/media/

        <Directory /usr/local/wsgi/static>
            Require all granted
        </Directory>

        WSGIScriptAlias / /usr/local/wsgi/scripts/myapp.wsgi

        <Directory /usr/local/wsgi/scripts>
            Require all granted
        </Directory>
    </VirtualHost>

When Apache is started as ``root`` the daemon processes can run as
a user different from the Apache child user. The number of
processes, the threads-per-process count, and a per-process
maximum-request limit are all configurable.

A few of the more commonly used options to ``WSGIDaemonProcess``:

**user=name | user=#uid**

    The UNIX user *name* or numeric user *uid* the daemon processes
    run as. Defaults to whatever user Apache runs its child
    processes as (the ``User`` directive). Ignored when Apache was
    not started as ``root`` — in that case daemon processes run as
    the user Apache was started as, regardless of this option.

**group=name | group=#gid**

    The UNIX group *name* or numeric group *gid* of the primary
    group the daemon processes run as. Defaults to the group from
    the ``Group`` directive. Same root-required caveat as ``user=``.

**processes=num**

    Number of daemon processes in the group. Default is one.

    Note: setting ``processes=1`` explicitly causes
    ``wsgi.multiprocess`` to be ``True`` in the WSGI environment,
    while *omitting* the option entirely causes
    ``wsgi.multiprocess`` to be ``False``. This is to allow
    front-end mapping mechanisms to distribute requests across
    multiple single-process daemon groups while still appearing
    multiprocess to the application. If your application requires
    ``wsgi.multiprocess`` to be ``False`` (for example, to run an
    interactive debugger), simply omit the ``processes`` option and
    accept the implied default of one.

**threads=num**

    Number of request-handling threads per daemon process. Default
    is 15.

**maximum-requests=nnn**

    Number of requests a daemon process handles before it is
    shutdown and restarted. Useful as a safety net for accidental
    memory leaks in long-running applications. Default is no
    limit.

    See also ``restart-interval`` (wall-clock time threshold),
    ``cpu-time-limit`` (CPU time threshold), and
    ``inactivity-timeout`` (idle threshold) for sibling
    process-recycling triggers.

For the full set of options, see
:doc:`../configuration-directives/WSGIDaemonProcess`.

Daemon process groups must have unique names across the server.
Two virtual hosts cannot both declare ``WSGIDaemonProcess myapp
...`` even if their other options differ.

When ``WSGIDaemonProcess`` is declared at server scope (outside any
``<VirtualHost>``), any virtual host can delegate to it. When
declared inside a ``<VirtualHost>``, only WSGI applications
associated with that same virtual host can delegate to it. See
:doc:`configuration-issues` for the failure modes around scoping
and naming.

A common multi-tenant setup is one daemon process group per virtual
host, each running as the user that owns the application::

    <VirtualHost *:80>
        ServerName www.site1.com
        CustomLog logs/www.site1.com-access_log common
        ErrorLog logs/www.site1.com-error_log

        WSGIDaemonProcess www.site1.com user=joe group=joe \
            processes=2 threads=25
        WSGIProcessGroup www.site1.com

        ...
    </VirtualHost>

    <VirtualHost *:80>
        ServerName www.site2.com
        CustomLog logs/www.site2.com-access_log common
        ErrorLog logs/www.site2.com-error_log

        WSGIDaemonProcess www.site2.com user=bob group=bob \
            processes=2 threads=25
        WSGIProcessGroup www.site2.com

        ...
    </VirtualHost>

The argument to ``WSGIProcessGroup`` is normally the name of a
declared daemon process group. Two special expanding values are
available:

**%{GLOBAL}**

    The process group name resolves to the empty string, which
    selects embedded mode rather than any daemon group. The
    application runs inside the Apache child processes, sharing
    process space with other Apache modules and running as the
    user Apache itself runs as.

**%{ENV:variable}**

    The process group name resolves to the value of the named
    environment variable, looked up via Apache's notes and
    subprocess environment data structures (and falling back to
    ``getenv()`` from the Apache server process). The result must
    name an existing daemon process group.

Environment variables for the ``%{ENV}`` lookup can be set with
``SetEnv`` and ``RewriteRule``. For example, to pick a process
group from a database keyed by request URI::

    RewriteEngine On
    RewriteMap wsgiprocmap dbm:/etc/httpd/wsgiprocmap.dbm
    RewriteRule . - [E=PROCESS_GROUP:${wsgiprocmap:%{REQUEST_URI}}]

    WSGIProcessGroup %{ENV:PROCESS_GROUP}

Applying a process-recycling trigger such as ``maximum-requests``
is recommended for any large application that depends on many
third-party packages, particularly applications that talk to a
database. Frameworks such as Django and Flask, and any application
using a long-lived connection pool, can benefit from periodic
recycling. If an application does not shut down cleanly when its
process is recycled it will be killed after the shutdown timeout
expires; if that happens regularly, run more than one process in
the group so that another process can continue serving requests
while the first restarts.

Daemon mode is not available on Windows. mod_wsgi on Windows
supports only embedded mode.

Defining Application Groups
---------------------------

Within a process — whether an Apache child process in embedded mode
or a daemon process — the WSGI application runs inside a Python
sub-interpreter. The sub-interpreter is identified by an
*application group* name. By default each WSGI application gets its
own application group, which means each one gets its own
sub-interpreter and its own copy of every imported Python module.

If a single process hosts many small WSGI applications and they can
safely share a Python module namespace, placing them all in the
same application group avoids the per-application memory overhead
of duplicate module imports. Use ``WSGIApplicationGroup``::

    <Directory /usr/local/wsgi/scripts>
        WSGIApplicationGroup admin-scripts
        Require all granted
    </Directory>

The argument can be any unique name, with two special expanding
values:

**%{GLOBAL}**

    The application runs in the main Python interpreter — the one
    Python creates at process startup, before any sub-interpreters
    are spawned.

    A small number of C extension modules — most commonly NumPy and
    SciPy, plus other modules built on the same simplified
    Python C API for GIL management — assume they are running in
    the main interpreter and misbehave inside sub-interpreters. The
    symptoms range from import errors to crashes once the
    extension is exercised. If your application uses such an
    extension directly or transitively, set ``WSGIApplicationGroup
    %{GLOBAL}`` for it. See :doc:`configuration-issues` for the
    full discussion.

**%{ENV:variable}**

    The application group name resolves to the value of the named
    environment variable, looked up the same way as for
    ``WSGIProcessGroup``.

See :doc:`../configuration-directives/WSGIApplicationGroup` for the
full list of expanding values and the matching rules.

As an example of using ``%{ENV:variable}``, to group all WSGI
scripts beneath a specific ``mod_userdir``-served user directory
into the same application group::

    RewriteEngine On
    RewriteCond %{REQUEST_URI} ^/~([^/]+)
    RewriteRule . - [E=APPLICATION_GROUP:~%1]

    <Directory /home/*/public_html/wsgi-scripts/>
        Options ExecCGI
        SetHandler wsgi-script
        WSGIApplicationGroup %{ENV:APPLICATION_GROUP}
    </Directory>

Application Configuration
-------------------------

To pass configuration values from the Apache configuration through
to the WSGI application, use ``SetEnv``::

    WSGIScriptAlias / /usr/local/wsgi/scripts/demo.wsgi

    SetEnv demo.templates /usr/local/wsgi/templates
    SetEnv demo.mailhost mailhost
    SetEnv demo.debugging 0

Variables set this way appear in the WSGI ``environ`` dictionary on
each request. They are *not* the same as ``os.environ`` — the
process environment is unaffected by ``SetEnv`` and there is no
mod_wsgi mechanism for setting process environment variables from
Apache configuration.

For request-dependent variables, ``RewriteRule`` can be used to set
variables conditionally::

    SetEnv demo.debugging 0

    RewriteEngine On
    RewriteCond %{REMOTE_ADDR} ^127.0.0.1$
    RewriteRule . - [E=demo.debugging:1]

For configuration that ``SetEnv`` and ``RewriteRule`` cannot
express, wrap the application inside its WSGI script file and
mutate the ``environ`` dictionary before delegating to the real
application::

    def _application(environ, start_response):
        ...

    def application(environ, start_response):
        if environ['REMOTE_ADDR'] == '127.0.0.1':
            environ['demo.debugging'] = '1'
        return _application(environ, start_response)

User Authentication
-------------------

By default Apache does not pass HTTP authorisation headers through
to WSGI applications, the same restriction it applies to CGI
scripts. The reason is the same: passing the authorisation header
through could leak credentials to a WSGI application that should
not see them when Apache is performing the authentication.

Set :doc:`../configuration-directives/WSGIPassAuthorization` to
``On`` to pass the ``Authorization`` HTTP request header through to
the application as the ``HTTP_AUTHORIZATION`` WSGI environment
variable. This is what you want when the WSGI application itself
implements authentication::

    WSGIPassAuthorization On

When Apache (rather than the WSGI application) performs the
authentication, the WSGI application can still see the result via
the ``AUTH_TYPE`` and ``REMOTE_USER`` environment variables —
``AUTH_TYPE`` indicates which authentication scheme Apache used,
``REMOTE_USER`` is the authenticated login name.

Limiting Request Content
------------------------

By default Apache imposes no limit on the size of a request body.
A WSGI application that reads the entire request body into memory
will exhaust available memory under a malicious upload, regardless
of any size checks the application itself implements.

Set Apache's ``LimitRequestBody`` to a sensible upper bound on the
request body size for the application::

    LimitRequestBody 1048576

The argument is the maximum number of bytes allowed in the request
body. mod_wsgi performs the check before the WSGI application is
invoked: when the limit is exceeded mod_wsgi returns a ``413``
response and closes the client connection without ever calling the
application. The ``413`` response page is whatever Apache or the
applicable ``ErrorDocument`` directive defines.

Reverse Proxy And HTTPS Termination
-----------------------------------

A common production deployment pattern places mod_wsgi behind a
separate reverse proxy that terminates TLS — typically nginx,
HAProxy, or a managed load balancer such as AWS ALB. mod_wsgi sees
plain HTTP requests on a private interface and information about
the original client connection (real IP, original protocol,
original Host header) is carried in HTTP headers added by the
proxy.

For the WSGI application to see the original client information
rather than the connection-level details between the proxy and
Apache, mod_wsgi must be told which front-end proxies are trusted
and which headers to honour. The two relevant directives are:

* :doc:`../configuration-directives/WSGITrustedProxies` — IP
  addresses or CIDR ranges of front-end proxies whose forwarded
  headers should be trusted.
* :doc:`../configuration-directives/WSGITrustedProxyHeaders` —
  which proxy headers (``X-Forwarded-For``, ``X-Forwarded-Proto``,
  ``X-Forwarded-Host``, etc.) to consume.

Without these directives the WSGI environment keys ``REMOTE_ADDR``,
``HTTP_HOST``, and ``wsgi.url_scheme`` reflect the connection
between the proxy and Apache, not the original client request. With
the directives in place mod_wsgi rewrites those keys based on the
trusted proxy headers so the application sees the original client
context.

A typical configuration for a single trusted front-end proxy at
``192.0.2.10``::

    WSGITrustedProxies 192.0.2.10
    WSGITrustedProxyHeaders X-Forwarded-For X-Forwarded-Proto \
        X-Forwarded-Host

Trust only the proxies you actually operate. ``WSGITrustedProxies``
defaults to no trusted proxies (that is, the forwarded headers are
ignored regardless of source) for safety; trusting an arbitrary
client to set ``X-Forwarded-For`` is an authentication bypass for
applications that gate behaviour on ``REMOTE_ADDR``.

The Apache Alias Directive
--------------------------

``WSGIScriptAlias`` is the recommended way to mount a WSGI
application. As an alternative, the standard Apache ``Alias``
directive can be combined with ``SetHandler`` or ``AddHandler`` to
designate URLs as WSGI scripts. This pattern is mostly relevant
when WSGI scripts need to coexist with static files, CGI scripts,
or directory indexes in the same directory — situations the
``WSGIScriptAlias`` form does not address.

The equivalent of::

    WSGIScriptAlias /wsgi/ /usr/local/wsgi/scripts/

    <Directory /usr/local/wsgi/scripts>
        Require all granted
    </Directory>

using ``Alias`` plus ``SetHandler`` is::

    Alias /wsgi/ /usr/local/wsgi/scripts/

    <Directory /usr/local/wsgi/scripts>
        Options ExecCGI
        SetHandler wsgi-script
        Require all granted
    </Directory>

The differences from ``WSGIScriptAlias`` are that ``Options
ExecCGI`` must be enabled explicitly, and the ``wsgi-script``
handler must be designated explicitly (``WSGIScriptAlias`` does
both implicitly).

Mixed content directories
~~~~~~~~~~~~~~~~~~~~~~~~~

To mix static files, CGI scripts, and WSGI applications in one
directory, use ``AddHandler`` instead of ``SetHandler`` so the
handler is selected by file extension::

    Alias /wsgi/ /usr/local/wsgi/scripts/

    <Directory /usr/local/wsgi/scripts>
        Options ExecCGI

        AddHandler cgi-script .cgi
        AddHandler wsgi-script .wsgi

        Require all granted
    </Directory>

For whichever extensions you use, make sure no earlier
configuration applies a different handler to those same extensions
in the same context — if both ``cgi-script`` and ``wsgi-script``
are bound to the same extension the order of the directives
determines which wins, and the wrong handler may be selected.

To allow the extension to be omitted from the URL, add Apache's
``MultiViews`` option and configure ``MultiviewsMatch`` to consider
handlers when matching::

    <Directory /usr/local/wsgi/scripts>
        Options ExecCGI MultiViews
        MultiviewsMatch Handlers

        AddHandler cgi-script .cgi
        AddHandler wsgi-script .wsgi

        Require all granted
    </Directory>

This is most useful when migrating from CGI to WSGI without
changing existing URLs — Apache picks the WSGI version of a
resource over the CGI version when both exist.

To enable directory listings or directory indexes alongside the
WSGI handler::

    <Directory /usr/local/wsgi/scripts>
        Options ExecCGI Indexes

        DirectoryIndex index.html index.wsgi index.cgi

        AddHandler cgi-script .cgi
        AddHandler wsgi-script .wsgi

        Require all granted
    </Directory>

``DirectoryIndex`` only works for a WSGI application that returns a
single page when the URL maps directly to the directory itself —
it is not invoked when the request URL has additional path
information beyond the directory mount point. It cannot be used to
route a complex multi-URL application.

Per-directory configuration via .htaccess
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

``AddHandler`` and ``SetHandler`` can be placed in a ``.htaccess``
file inside the directory in question, provided ``AllowOverride
FileInfo`` is set on the parent directory (or wider) and ``Options
ExecCGI`` is permitted there::

    Alias /site/ /usr/local/wsgi/site/

    <Directory /usr/local/wsgi/site>
        AllowOverride FileInfo
        Options ExecCGI MultiViews Indexes
        MultiviewsMatch Handlers
        Require all granted
    </Directory>

The ``.htaccess`` file inside ``/usr/local/wsgi/site`` can then
contain::

    DirectoryIndex index.html index.wsgi index.cgi

    AddHandler cgi-script .cgi
    AddHandler wsgi-script .wsgi

Note that ``WSGIScriptAlias`` itself cannot be used in
``.htaccess``; only the per-directory directives are valid there.
See :doc:`configuration-issues` for which mod_wsgi directives are
allowed in ``.htaccess``.

Mounting a script-extension WSGI application at the site root
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

When using ``AddHandler`` with WSGI scripts identified by extension,
the only way to make the application appear at the site root is via
``mod_rewrite``. To make ``site.wsgi`` (in the document root)
respond to every URL on the virtual host::

    RewriteEngine On
    RewriteCond %{REQUEST_FILENAME} !-f
    RewriteRule ^(.*)$ /site.wsgi/$1 [QSA,PT,L]

The ``[PT]`` (pass-through) flag is required so that the rewrite is
re-resolved through the alias and handler phases.

A side effect of this rewrite is that the WSGI ``SCRIPT_NAME``
environment variable is ``/site.wsgi`` rather than ``/`` — which
will leak into any URLs the application generates from
``SCRIPT_NAME``. Many frameworks expose a configuration option to
override the mount point. As a fallback, wrap the application
inside the script file to rewrite ``SCRIPT_NAME`` before delegating::

    import posixpath

    def _application(environ, start_response):
        # The original application.
        ...

    def application(environ, start_response):
        environ['SCRIPT_NAME'] = posixpath.dirname(environ['SCRIPT_NAME'])
        if environ['SCRIPT_NAME'] == '/':
            environ['SCRIPT_NAME'] = ''
        return _application(environ, start_response)

This is an advanced pattern; in most cases ``WSGIScriptAlias /``
plus ``Alias`` directives for static files (described in `Hosting
Of Static Files`_ above) is the simpler and recommended approach.
