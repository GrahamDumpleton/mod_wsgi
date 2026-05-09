==============================
Running mod_wsgi-express
==============================

``mod_wsgi-express`` is the admin command installed alongside the
``mod_wsgi`` Python package. It builds the mod_wsgi Apache module
against the Apache and Python on your host, generates a
self-contained Apache configuration tuned for hosting a single
WSGI application, and starts an Apache instance owned by your
user.

This page picks up from :doc:`../getting-started`, which already
covers the first-run "Hello world" with ``mod_wsgi-express
start-server``. Here the focus is on the operational shape:
common options, running on privileged ports, dealing with
non-standard Apache layouts, the Django integration, and using
``mod_wsgi-express`` under a process supervisor or in a
container.

For installing the ``mod_wsgi`` package itself, see
:doc:`installation-from-pypi`.

Subcommands
-----------

``mod_wsgi-express`` is invoked as ``mod_wsgi-express <command>``.
The commands fall into two groups.

For running an Apache instance hosting your WSGI application:

* ``start-server`` runs an Apache instance in the foreground,
  hosting the WSGI script you supply. This is the common case
  during development and the typical entry point under a process
  supervisor.
* ``setup-server`` writes out the same configuration plus a
  generated ``apachectl`` wrapper, but does not start Apache.
  Used for daemonised init-script style deployments where Apache
  is started and stopped separately. See `Running on a privileged
  port`_ below.

For wiring the pip-built mod_wsgi module into a system Apache:

* ``module-config`` prints the ``LoadModule`` and
  ``WSGIPythonHome`` lines needed to reference the module from
  inside the Python install.
* ``install-module`` copies the module into Apache's modules
  directory and prints the corresponding ``LoadModule`` line.
* ``module-location`` prints just the filesystem path to the
  built module.

The ``module-config`` and ``install-module`` paths are covered in
detail under "Connecting the pip-built module to system Apache"
in :doc:`installation-from-pypi`.

Common options
--------------

The full option list is large; ``mod_wsgi-express start-server
--help`` is the canonical reference. The options most likely to
come up are:

``--port NUMBER``
    Port to listen on. Defaults to 8000.

``--host IP-ADDRESS``
    Host interface to bind. Defaults to all interfaces.

``--processes NUMBER``
    Number of daemon-mode worker processes. Defaults to 1.

``--threads NUMBER``
    Threads per worker process. Defaults to 5.

``--user USERNAME`` / ``--group GROUP``
    User and group the daemon process should run as. Required
    when starting as root, ignored otherwise. See `Running on a
    privileged port`_.

``--reload-on-changes``
    Restart the daemon process whenever any Python source file
    that the WSGI application has imported is modified, not just
    the WSGI entrypoint script itself. A background monitor
    thread polls ``sys.modules`` once a second, stat()s every
    loaded module's source file, and triggers a restart on the
    first change it sees. **For development use only.** It is
    not safe in production: every loaded module is stat()'d on
    every poll cycle (so cost scales with the size of the
    application), and any in-flight requests are interrupted
    when the daemon is restarted. Without this option,
    daemon-mode reloading still picks up changes to the WSGI
    entrypoint script file alone (the default mod_wsgi
    behaviour). See :doc:`reloading-source-code` for the broader
    reloading model.

``--log-to-terminal``
    Write Apache's access and error logs to standard output and
    standard error rather than to files under the server root.
    Required when running under a process supervisor or in a
    container that expects logs on the terminal.

``--server-root DIRECTORY-PATH``
    Where the generated configuration files and runtime state
    live. Defaults to a directory under ``/tmp``. Override this
    for ``setup-server`` so the configuration persists across
    reboots.

``--application-type TYPE``
    Defaults to ``script`` (a WSGI script file specified by
    filesystem path). Can also be ``module`` (a Python module
    name imported through the standard import mechanism) or
    ``static`` (serve a directory of static files only).

Hosting static files
--------------------

For applications that do not have static-file routing wired
up by their framework, ``mod_wsgi-express`` can serve static
assets directly from Apache rather than routing them through
the WSGI application. The ``--url-alias`` option maps a URL
prefix to a file or directory on disk; it is the express
equivalent of Apache's ``Alias`` directive.

To serve a directory of CSS, JavaScript, and image assets at
the ``/static/`` URL::

    mod_wsgi-express start-server wsgi.py \
        --url-alias /static/ /srv/myapp/static/

A ``GET /static/site.css`` request is now served by Apache
directly out of ``/srv/myapp/static/site.css`` without
entering the WSGI application.

The option is repeatable, and the second argument can be
either a directory or a single file. A typical mix::

    mod_wsgi-express start-server wsgi.py \
        --url-alias /static/ /srv/myapp/static/ \
        --url-alias /media/ /srv/myapp/media/ \
        --url-alias /favicon.ico /srv/myapp/static/favicon.ico \
        --url-alias /robots.txt /srv/myapp/static/robots.txt

The single-file form (the last two lines above) maps just
that one file to the exact URL given. Apache requires
longer/more-specific URL prefixes to be configured before
shorter ones, but ``mod_wsgi-express`` sorts the aliases
internally so the order on the command line does not
matter.

A separate ``--document-root`` option sets Apache's
``DocumentRoot`` directly. Files inside the document root
are reachable at their corresponding URL paths without
needing an alias. This is most useful when the WSGI
application is mounted at a sub-URL via ``--mount-point``
and the document root holds the rest of the site::

    mod_wsgi-express start-server wsgi.py \
        --mount-point /api/ \
        --document-root /srv/myapp/public/

In this example the WSGI application handles requests under
``/api/...`` while Apache serves the contents of
``/srv/myapp/public/`` at all other URLs. The default for
``--mount-point`` is ``/``, which is the typical "WSGI
application at the root, static assets at sub-URLs" shape
and is what the ``--url-alias`` examples above assume.

When ``mod_wsgi-express`` runs behind a reverse proxy,
static files served this way are subject to the same
``Location`` header rewriting and HTML-body URL leakage
caveats as the WSGI application itself; see
:doc:`running-behind-a-reverse-proxy`.

Other static-file options
-------------------------

Beyond ``--url-alias`` and ``--document-root``, a few
options shape how Apache handles requests that map to
the document root or to ``--url-alias``-mapped
directories:

``--directory-index FILE-NAME``
    Name of the index resource Apache serves when a
    request maps to a directory rather than a file (for
    example ``index.html``). Equivalent to Apache's
    ``DirectoryIndex``. Without it, a directory request
    is passed through to the WSGI application or, if
    the document root is the static target, returns
    404.

``--directory-listing``
    Enable Apache's automatic directory listing when a
    request maps to a directory and no
    ``--directory-index`` match is found. Off by
    default. Most useful with
    ``--application-type static``; rarely useful when
    a WSGI application is also mounted.

``--allow-override DIRECTIVE-TYPE``
    Permit ``.htaccess`` files inside the document root
    or ``--url-alias``-mapped directories to override
    the named Apache directive types. Defaults to
    ``None`` (``.htaccess`` ignored). Repeatable to
    list more than one directive type. Equivalent to
    Apache's ``AllowOverride``.

``--error-document STATUS URL-PATH``
    Replace Apache's default error page for the given
    HTTP status code with a static resource at the
    named URL. Repeatable. Equivalent to Apache's
    ``ErrorDocument``::

        mod_wsgi-express start-server wsgi.py \
            --error-document 404 /errors/404.html \
            --error-document 500 /errors/500.html

    The named URL paths typically resolve to files
    served from the document root or from a
    ``--url-alias``-mapped directory.

``--error-override``
    Make Apache's error documents replace the WSGI
    application's error responses. Without this flag
    the WSGI application's response body is sent
    through to the client as-is; with it, Apache
    substitutes the matching ``ErrorDocument`` page.
    Useful when the deployment should present a
    uniform error experience across the WSGI
    application and any co-hosted static content.
    Daemon mode only; has no effect under
    ``--embedded-mode``.

Server name and virtual hosts
-----------------------------

By default ``mod_wsgi-express`` accepts requests on
the configured port regardless of the host header.
The following options shape its name-based
virtual-host behaviour, which matters when the
express instance is fronted by a reverse proxy that
routes by hostname, or when the same instance hosts
more than one hostname.

``--server-name HOSTNAME``
    The primary host name the server identifies as.
    Generates the Apache ``ServerName`` directive.
    When ``HOSTNAME`` begins with ``www.``,
    ``mod_wsgi-express`` also adds an automatic
    redirect from the parent domain (without
    ``www.``) to the ``www.`` form.

``--server-alias HOSTNAME``
    Additional host name served by the same WSGI
    application. Generates the Apache
    ``ServerAlias`` directive. Repeatable, and
    wildcard patterns (``*.example.com``) are
    accepted.

``--allow-localhost``
    Allow ``localhost`` (and ``127.0.0.1``) to reach
    the WSGI application even when ``--server-name``
    is set to a different public hostname. By default
    the name-based virtual-host gate rejects requests
    that do not match the server name; this flag
    keeps a side door open for health checks,
    sidecars, and other on-host clients that connect
    by loopback.

Environment plumbing
--------------------

Several options shape the runtime environment the
WSGI application sees, both at process startup and
per request.

``--working-directory DIRECTORY-PATH``
    The current working directory of the WSGI
    application. Defaults to the directory the
    ``mod_wsgi-express`` command was run from, which
    can be a surprising value (the user's home, the
    directory ``systemd`` placed the unit in, the
    directory ``cron`` ran the job from). Set this
    explicitly. The directory is also searched for
    Python imports unless the application later
    changes its working directory.

``--python-path DIRECTORY-PATH``
    Additional directory added to ``sys.path``.
    Repeatable. ``.pth`` files in these directories
    are not processed; if ``.pth`` processing is
    needed, set ``PYTHONPATH`` via an
    ``--envvars-script`` instead.

``--python-eggs DIRECTORY-PATH``
    Directory used for unpacking Python eggs.
    Defaults to a sub-directory of the server root.
    Override when the server root is on a tmpfs or
    transient filesystem and the egg cache should
    persist across restarts.

``--locale NAME``
    Locale for the WSGI process, equivalent to
    setting ``LC_ALL``. If unset and the inherited
    locale is ``C`` or ``POSIX``, ``mod_wsgi-express``
    tries ``en_US.UTF-8``, then ``C.UTF-8``, falling
    back to the inherited locale if neither is
    available. The fallback chain avoids the silent
    ASCII-only behaviour that follows from running
    under ``C``.

``--setenv KEY VALUE``
    Add a name/value pair to every request's WSGI
    ``environ`` dictionary. Repeatable. Useful for
    static configuration the application reads from
    ``environ`` rather than from the OS process
    environment.

``--passenv KEY``
    Pass a named OS process environment variable
    into every request's WSGI ``environ`` dictionary
    as a name/value pair. Repeatable. The express
    invocation must already have the variable in
    its process environment (typically via the
    supervisor unit, the container runtime, or the
    user's shell).

Compression
-----------

``--compress-responses``
    Enable compression of common text-based response
    types (plain text, HTML, XML, CSS, JavaScript).
    Off by default. Generates the Apache
    ``mod_deflate`` configuration that compresses
    responses for clients advertising
    ``Accept-Encoding: gzip`` or ``deflate``.

When ``mod_wsgi-express`` runs behind a front-end
proxy, response compression is more often handled at
the proxy than at the back-end. Using both is
wasteful (double compression and decompression at
the proxy), so enable this flag only when the
express instance is the front-line server.

Running on a privileged port
----------------------------

To listen on a privileged port such as 80 or 443,
``mod_wsgi-express`` needs to be started as root. Apache's
parent process binds the listening socket as root and then
drops privileges; the ``--user`` and ``--group`` options say
which account the daemon process should switch to. Most Linux
distributions predefine a service account for Apache (e.g.
``www-data`` on Debian/Ubuntu, ``apache`` on RHEL/Fedora) which
can be reused, or you can use any other dedicated account.

There are two patterns, depending on whether the running process
is supervised externally or expected to daemonise itself.

Foreground under a process supervisor
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

For systemd, supervisord, or a container init that expects a
foreground process, use ``start-server`` directly with
``--user`` and ``--group``::

    sudo mod_wsgi-express start-server wsgi.py --port=80 \
        --user www-data --group www-data \
        --log-to-terminal

The supervisor handles restart on failure; mod_wsgi-express
itself stays in the foreground and writes logs to the terminal.

Daemonised with a generated apachectl
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

For a traditional init-script deployment where separate
``start`` / ``stop`` / ``restart`` commands are expected and
the running process is meant to daemonise, use ``setup-server``
instead. It writes out the configuration and a wrapper
``apachectl`` script but does not start Apache::

    sudo mod_wsgi-express setup-server wsgi.py --port=80 \
        --user www-data --group www-data \
        --server-root=/etc/mod_wsgi-express-80

Apache is then started, stopped, and restarted through the
generated wrapper::

    /etc/mod_wsgi-express-80/apachectl start
    /etc/mod_wsgi-express-80/apachectl stop
    /etc/mod_wsgi-express-80/apachectl restart

The original ``setup-server`` options are cached inside the
server root, so subsequent ``apachectl`` invocations reuse the
same configuration. To change options, re-run ``setup-server``
with the new options.

SELinux
~~~~~~~

On RHEL, Fedora, AlmaLinux, and Rocky Linux, SELinux is enforcing
by default. The bundled SELinux policy expects Apache to start
from a specific binary path and to read configuration from
specific paths. Starting Apache through ``mod_wsgi-express`` will
not match those expectations out of the box, and may fail with
``Permission denied`` errors that are not visible in the Apache
error log because SELinux blocks them at the kernel boundary.
Two workarounds:

* Move the directory specified with ``--server-root`` to a
  location SELinux already permits Apache to read.
* Adjust the SELinux policy to permit the ``--server-root``
  location.

For brief experiments, ``setenforce 0`` will disable SELinux
enforcement until reboot, but is not appropriate for any kind of
production use.

Non-standard Apache layouts
---------------------------

Several Linux distributions rename the Apache binary, or replace
it with a shell script that performs additional setup before
exec'ing the real binary. ``mod_wsgi-express`` looks for an
executable called ``httpd`` by default, so a renamed binary
will fail to start with a "command not found" style error.

Use ``--httpd-executable`` to point at the real binary::

    mod_wsgi-express start-server wsgi.py \
        --httpd-executable=/usr/sbin/apache2

If the distribution has wrapped ``httpd`` with a shell script and
the shell script is interfering with ``mod_wsgi-express`` (for
example, by requiring root privileges to perform other setup
steps), point ``--httpd-executable`` at whichever binary the
shell script ultimately exec's.

Django integration
------------------

``mod_wsgi-express`` can be invoked through Django's
``manage.py`` so that it picks up the Django project's settings
and static files automatically.

Add ``mod_wsgi.server`` to ``INSTALLED_APPS`` in the Django
settings module::

    INSTALLED_APPS = [
        'django.contrib.admin',
        'django.contrib.auth',
        'django.contrib.contenttypes',
        'django.contrib.sessions',
        'django.contrib.messages',
        'django.contrib.staticfiles',
        'mod_wsgi.server',
    ]

Collect static assets into the directory the Django settings
designate for them::

    python manage.py collectstatic

Then start the server through Django::

    python manage.py runmodwsgi

This is equivalent to ``mod_wsgi-express start-server`` against
the Django project's ``wsgi.py``, with static-file URLs and
asset roots wired up from the Django settings.

For development, ``--reload-on-changes`` makes the daemon
restart whenever any Python file the application has imported is
modified (not just the WSGI script)::

    python manage.py runmodwsgi --reload-on-changes

Use this only during development; see the option description
above for why it is not appropriate for production.

For the daemonised root deployment described above, the
equivalent of ``setup-server`` is ``--setup-only``::

    python manage.py runmodwsgi --setup-only --port=80 \
        --user www-data --group www-data \
        --server-root=/etc/mod_wsgi-express-80

The generated ``apachectl`` is then used in the same way as for
the standalone ``setup-server`` flow.

Process supervisors and containers
----------------------------------

When ``mod_wsgi-express`` runs under a process supervisor
(systemd, supervisord, runit, s6) or as the main process inside
a container, two things change relative to running it
interactively:

* Logs need to go to standard output and standard error rather
  than to files under the server root, so the supervisor or
  container runtime can collect them. Pass ``--log-to-terminal``.
* Apache must remain in the foreground so the supervisor sees it
  as a running process. ``start-server`` already runs in the
  foreground, so no additional flag is needed.

For a Dockerfile walkthrough including base-image package
requirements, the PID 1 reaping behaviour, and running as a
non-root user inside the container, see
:doc:`installing-with-docker`.

Logging
-------

By default ``mod_wsgi-express`` writes its Apache error
log to a file under the server root and does not write
an access log at all. Several options shape what gets
logged and where it goes.

``--log-to-terminal``
    Send Apache's access and error logs to standard
    output / standard error rather than to files. Used
    under a process supervisor or in a container; see
    `Process supervisors and containers`_. When
    ``--log-directory`` is also set, ``--log-directory``
    wins.

``--access-log``
    Enable the Apache access log. Off by default;
    enabling it adds a ``CustomLog`` directive to the
    generated configuration. The destination is governed
    by ``--log-to-terminal``, ``--log-directory`` and
    ``--access-log-name``.

``--startup-log``
    Enable a separate startup log file capturing
    Apache's own startup-phase output. Off by default;
    enable when troubleshooting startup failures.

``--log-directory DIRECTORY-PATH``
    Directory the log files are written to. Defaults to
    the server root. Override to redirect logs to a
    persistent or distinct location.

``--log-level NAME``
    Apache ``LogLevel`` value. Defaults to ``warn``.
    Raise to ``info`` or ``debug`` only when
    troubleshooting; verbose levels emit per-request
    detail and grow the log quickly.

``--access-log-name FILE-NAME`` / ``--error-log-name FILE-NAME`` / ``--startup-log-name FILE-NAME``
    File names for the access, error and startup logs
    when they are written to the log directory.
    Defaults are ``access_log``, ``error_log`` and
    ``startup_log`` respectively.

``--access-log-format FORMAT``
    Format string for access log records. The values
    ``common`` and ``combined`` are recognised as
    Apache log-format nicknames; any other value is
    used verbatim as the ``LogFormat`` directive value.

``--error-log-format FORMAT``
    Format string for error log records. Used verbatim
    as the Apache ``ErrorLogFormat`` directive value.

``--rotate-logs``
    Pipe log output through Apache's ``rotatelogs``
    helper so files rotate at a size threshold. Off by
    default. Has no effect when ``--log-to-terminal``
    is on, since rotation is meaningless against
    standard streams.

``--max-log-size MB``
    Size threshold in megabytes for log rotation when
    ``--rotate-logs`` is on. Defaults to 5.

``--rotatelogs-executable FILE-PATH``
    Path to the ``rotatelogs`` binary. Defaults to the
    one discovered alongside the system Apache; set
    when ``rotatelogs`` is in a non-standard location
    or has been renamed.

Custom Apache configuration
---------------------------

``mod_wsgi-express`` generates a complete Apache
configuration from its options, but a few escape
hatches allow hand-written Apache directives or
shell-level setup to be injected without giving up
the ``mod_wsgi-express`` flow:

``--include-file FILE-PATH``
    Path to a file of additional Apache directives
    appended at the end of the generated
    configuration. Use for directives that have no
    ``mod_wsgi-express`` option of their own
    (security headers, custom ``Location`` blocks,
    third-party module configuration). Repeatable.

``--rewrite-rules FILE-PATH``
    Path to a file of ``mod_rewrite`` rules included
    inside the generated configuration. Defaults to
    ``rewrite.conf`` under the server root if such a
    file exists. Override when the rules live
    alongside the application source rather than
    inside the generated server root.

``--envvars-script FILE-PATH``
    Path to a shell script sourced before Apache
    starts. Use to set process-level environment
    variables (``DATABASE_URL``,
    ``OAUTH_CLIENT_SECRET``, ``PYTHONPATH``) that
    the WSGI application reads at import time, or
    that other Apache modules consult during
    startup. Defaults to ``envvars`` under the
    server root if such a file exists.

Where to go next
----------------

* :doc:`../configuration` and the
  :doc:`../configuration-directives/WSGIDaemonProcess` directive
  for what ``mod_wsgi-express`` is generating under the hood.
* :doc:`configuration-guidelines` for richer configuration
  examples once you outgrow ``mod_wsgi-express`` and move to a
  hand-written Apache configuration.
* :doc:`processes-and-threading` for choosing values for
  ``--processes`` and ``--threads``.
* :doc:`debugging-techniques` and :doc:`application-issues` when
  things go wrong.
