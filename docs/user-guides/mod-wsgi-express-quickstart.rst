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
(systemd, supervisord, runit, s6) or as a container ``CMD``,
two things change relative to running it interactively:

* Logs need to go to standard output and standard error rather
  than to files under the server root, so the supervisor or
  container runtime can collect them. Pass ``--log-to-terminal``.
* Apache must remain in the foreground so the supervisor sees it
  as a running process. ``start-server`` already runs in the
  foreground, so no additional flag is needed.

A typical container ``CMD`` looks like::

    CMD ["mod_wsgi-express", "start-server", "wsgi.py", \
         "--port=80", "--log-to-terminal", \
         "--user=www-data", "--group=www-data"]

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
