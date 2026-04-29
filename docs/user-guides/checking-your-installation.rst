==========================
Checking Your Installation
==========================

When debugging mod_wsgi or a WSGI application it is important to be
able to confirm which Apache and which Python mod_wsgi is running
against, how those installations were built, and what configuration
the WSGI application is running under. This page lists the checks
that gather that information.

The primary purpose of the page is to give a single reference for
the diagnostic data that maintainers ask for when responding to a
GitHub issue. If you have been directed here to collect information
for a bug report, include the *full* output of the checks rather
than a summary — partial output makes it harder to rule out causes.

Apache build information
------------------------

The first piece of information to collect is which Apache binary is
in use and how it was built. The starting point is ``httpd -V``::

    $ httpd -V
    Server version: Apache/2.4.66 (Unix)
    Server built:   Dec  1 2025 12:44:02
    Server's Module Magic Number: 20120211:141
    Server loaded:  APR 1.7.6, APR-UTIL 1.6.3, PCRE 10.47 2025-10-21
    Compiled using: APR 1.7.6, APR-UTIL 1.6.3, PCRE 10.47 2025-10-21
    Architecture:   64-bit
    Server MPM:     prefork
      threaded:     no
        forked:     yes (variable process count)
    Server compiled with....
     -D APR_HAS_SENDFILE
     -D APR_HAS_MMAP
     -D APR_HAVE_IPV6 (IPv4-mapped addresses enabled)
     -D APR_USE_SYSVSEM_SERIALIZE
     -D APR_USE_PTHREAD_SERIALIZE
     -D SINGLE_LISTEN_UNSERIALIZED_ACCEPT
     -D APR_HAS_OTHER_CHILD
     -D AP_HAVE_RELIABLE_PIPED_LOGS
     -D DYNAMIC_MODULE_LIMIT=256
     -D HTTPD_ROOT="/opt/homebrew/Cellar/httpd/2.4.66"
     -D SUEXEC_BIN="/opt/homebrew/opt/httpd/bin/suexec"
     -D DEFAULT_PIDLOG="/opt/homebrew/var/run/httpd/httpd.pid"
     -D DEFAULT_SCOREBOARD="logs/apache_runtime_status"
     -D DEFAULT_ERRORLOG="logs/error_log"
     -D AP_TYPES_CONFIG_FILE="/opt/homebrew/etc/httpd/mime.types"
     -D SERVER_CONFIG_FILE="/opt/homebrew/etc/httpd/httpd.conf"

The example above is from a Homebrew-installed Apache on macOS. The
fields you should report when filing an issue are:

* The Apache version, from ``Server version``.
* The MPM, from ``Server MPM``. Common values are ``event`` (the
  Apache 2.4 default on most Linux distributions), ``worker``, and
  ``prefork``.
* The architecture and APR/APR-UTIL versions, from the matching
  fields.

The location of the Apache executable depends on how Apache was
installed: ``/usr/sbin/httpd`` (RHEL family), ``/usr/sbin/apache2``
(Debian/Ubuntu), and ``/opt/homebrew/bin/httpd`` (Homebrew on
Apple Silicon macOS) or ``/usr/local/bin/httpd`` (Homebrew on
Intel macOS) are all common.

The ``-D`` block in the output is a curated subset of compile-time
defines, not the full set of ``configure`` arguments. If you need
the actual ``configure`` invocation that was used to build Apache,
look for a ``config.nice`` file in Apache's build directory.
``config.nice`` is generated alongside the build and recorded for
reference. ``apxs -q installbuilddir`` reports where Apache thinks
the build directory is::

    $ apxs -q installbuilddir
    /opt/homebrew/opt/httpd/lib/httpd/build
    $ cat /opt/homebrew/opt/httpd/lib/httpd/build/config.nice

Apache modules loaded
---------------------

Apache modules can be statically compiled into the ``httpd`` binary
or loaded dynamically from configuration. ``httpd -l`` lists the
statically compiled set::

    $ httpd -l
    Compiled in modules:
      core.c
      mod_so.c
      http_core.c

On almost all modern Apache builds this is a small fixed set
including ``mod_so.c``, which is the module that loads other
modules dynamically.

``httpd -M`` lists every module that will be loaded for the current
configuration — both the statically compiled modules and any
``LoadModule`` directives in the active config files::

    $ httpd -M
    Loaded Modules:
     core_module (static)
     so_module (static)
     http_module (static)
     mpm_prefork_module (shared)
     authn_file_module (shared)
     authn_core_module (shared)
     authz_host_module (shared)
     authz_groupfile_module (shared)
     authz_user_module (shared)
     authz_core_module (shared)
     access_compat_module (shared)
     auth_basic_module (shared)
     reqtimeout_module (shared)
     filter_module (shared)
     mime_module (shared)
     log_config_module (shared)
     env_module (shared)
     headers_module (shared)
     setenvif_module (shared)
     version_module (shared)
     unixd_module (shared)
     status_module (shared)
     autoindex_module (shared)
     dir_module (shared)
     alias_module (shared)
     wsgi_module (shared)

The names match what would be used in a ``LoadModule`` directive,
not the module file names on disk. The order in which modules
appear matters when two modules can both handle a request and
neither explicitly designates a relative dispatch order.

Confirm that ``wsgi_module`` is present in the list. If it isn't,
either the ``LoadModule`` directive is missing or Apache is
rejecting the load — check the Apache error log for a load-time
diagnostic.

Cross-process mutex
-------------------

Apache uses a global cross-process mutex to serialise which child
process accepts the next incoming connection. mod_wsgi separately
uses a similar mutex per daemon process group to serialise which
daemon-process worker accepts the next request proxied to the
group. The mutex mechanism — ``flock``, ``fcntl``, ``sysvsem``,
``posixsem``, or ``pthread`` — varies by platform and can be
overridden in configuration.

Under normal circumstances the platform default is fine and you
should not need to override it. The information becomes relevant
when reporting an issue that involves stalls or deadlocks between
Apache children and mod_wsgi daemon workers.

Which mechanism Apache uses by default for the accept mutex can be
read from the ``-D`` block in the ``httpd -V`` output above — the
``APR_USE_*_SERIALIZE`` lines describe the platform default. In the
example above the lines are::

    -D APR_USE_SYSVSEM_SERIALIZE
    -D APR_USE_PTHREAD_SERIALIZE

The ``USE`` lines are interpreted in order, so this example shows
``sysvsem`` as the default. mod_wsgi uses the same default for its
daemon-process-group mutex.

The default can be overridden for Apache itself via the ``Mutex``
directive (Apache 2.4 replaced the older ``AcceptMutex`` directive
with a more general ``Mutex`` directive that takes a mutex name).
For mod_wsgi's daemon-process-group mutex, the override directive
is :doc:`../configuration-directives/WSGIAcceptMutex` instead;
``Mutex`` does not affect mod_wsgi.

The set of mechanisms available on a given platform is whichever
``APR_HAS_*_SERIALIZE`` macros are defined to ``1`` in ``apr.h``.
The simplest way to discover the available set without locating
``apr.h`` is to put a deliberately invalid value into the
configuration and run ``httpd -t``::

    $ httpd -t
    AH00526: Syntax error on line N of /path/to/httpd.conf:
    Invalid Mutex argument xxx (Mutex mechanisms are: 'none', \
     'default', 'flock:/path/to/file', 'fcntl:/path/to/file', \
     'file:/path/to/file', 'sysvsem', 'posixsem', 'sem')

The same trick works for ``WSGIAcceptMutex`` once mod_wsgi is
loaded::

    httpd: Syntax error on line N of /path/to/httpd.conf: \
    Accept mutex lock mechanism 'xxx' is invalid. Valid accept \
    mutex mechanisms for this platform are: default, flock, \
    fcntl, sysvsem, posixsem.

``default`` defers the choice back to APR.

Python shared library
---------------------

mod_wsgi must be linked against Python via a shared library, not a
static one. A normally-built ``mod_wsgi.so`` is well under 1MB and
will show a ``libpython3.X.so`` line in ``ldd`` output on Linux::

    $ ldd mod_wsgi.so
     linux-vdso.so.1 =>  (0x00007fffeb3fe000)
     libpython3.12.so.1.0 => /usr/local/lib/libpython3.12.so.1.0 (0x00002adebf94d000)
     libpthread.so.0 => /lib/libpthread.so.0 (0x00002adebfcba000)
     libdl.so.2 => /lib/libdl.so.2 (0x00002adebfed6000)
     libutil.so.1 => /lib/libutil.so.1 (0x00002adec00da000)
     libc.so.6 => /lib/libc.so.6 (0x00002adec02dd000)
     libm.so.6 => /lib/libm.so.6 (0x00002adec0635000)
     /lib64/ld-linux-x86-64.so.2 (0x0000555555554000)

When checking, unset ``LD_LIBRARY_PATH`` first — ``ldd`` honours
it but Apache does not normally inherit it, so a check that
relies on ``LD_LIBRARY_PATH`` may give a misleadingly clean
result that doesn't match what Apache will see at startup.

On macOS, ``ldd`` is not available; use ``otool -L`` instead::

    $ otool -L mod_wsgi.so
    mod_wsgi.so:
      /opt/homebrew/opt/python@3.12/Frameworks/Python.framework/Versions/3.12/Python (compatibility version 3.12.0, current version 3.12.10)
      /usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1351.0.0)

If no ``libpython3.X.so`` (or framework) line appears, mod_wsgi was
built against a static Python library and a number of follow-on
issues apply. If the library appears but Apache fails to load
``mod_wsgi.so``, or appears but resolves to the wrong copy, that is
a separate runtime problem with its own workarounds. See
:doc:`installation-issues` for the full set of failure modes
("Lack Of Python Shared Library", "Unable To Find Python Shared
Library", and the related sections).

Python installation in use
--------------------------

Even when ``mod_wsgi.so`` links to the right ``libpython``, the
Python interpreter still needs to find the *installation* — the
matching ``lib/pythonX.Y/`` directory containing the standard
library and any installed packages.

The embedded Python locates this by searching ``PATH`` for its own
executable name and taking the parent of where it is found as
``sys.prefix``. Apache typically inherits a minimal ``PATH``, so
on hosts with multiple Python installations the wrong one can be
picked up.

The most reliable way to confirm what Python is actually in use at
runtime is to deploy the diagnostic WSGI script below and look at
the ``sys.prefix`` and ``sys.version`` lines.

If the discovered installation is wrong, override the choice with
the :doc:`../configuration-directives/WSGIPythonHome` directive,
pointing at the ``sys.prefix`` of the Python you want used::

    >>> import sys
    >>> print(sys.prefix)
    /usr/local

::

    WSGIPythonHome /usr/local

The full discussion of multi-Python hosts and how the embedded
Python finds its installation is in
:doc:`installation-issues` under "Multiple Python Versions".

Diagnostic WSGI script
----------------------

The remaining checks — what process group, application group, and
threading model the WSGI application is running under, plus the
Python identity values from the previous section — can all be
captured with one diagnostic WSGI script::

    import sys

    def application(environ, start_response):
        lines = [
            "mod_wsgi.process_group     = %r" % environ["mod_wsgi.process_group"],
            "mod_wsgi.application_group = %r" % environ["mod_wsgi.application_group"],
            "wsgi.multithread           = %r" % environ["wsgi.multithread"],
            "wsgi.multiprocess          = %r" % environ["wsgi.multiprocess"],
            "sys.version                = %r" % sys.version,
            "sys.prefix                 = %r" % sys.prefix,
            "sys.path                   = %r" % sys.path,
        ]
        body = ("\n".join(lines) + "\n").encode("utf-8")
        start_response("200 OK", [
            ("Content-Type", "text/plain"),
            ("Content-Length", str(len(body))),
        ])
        return [body]

Mount the script and visit its URL. The output values are
interpreted as follows.

**mod_wsgi.process_group** — name of the daemon process group the
request was dispatched to. An empty string means embedded mode
(the WSGI application is running inside an Apache child process,
not a mod_wsgi daemon process). A non-empty string is the name of
the daemon process group named by the active ``WSGIDaemonProcess``
/ ``WSGIProcessGroup`` configuration. Embedded mode is also what
``WSGIProcessGroup %{GLOBAL}`` selects explicitly.

**mod_wsgi.application_group** — name of the Python sub-interpreter
the application is running in. An empty string means the main
interpreter (``%{GLOBAL}``). The default when ``WSGIApplicationGroup``
is not set is ``%{RESOURCE}``, which produces a value composed
from the server name, the connection port (omitted for ports 80
and 443), and the WSGI mount point — for example::

    mod_wsgi.application_group = 'tests.example.com|/interpreter.wsgi'

**wsgi.multithread** — ``True`` if the WSGI application is running
in a multithreaded environment, ``False`` if not. Daemon mode
defaults to multithreaded. Embedded mode is multithreaded under
the Event and Worker MPMs and single-threaded under the Prefork
MPM. If ``True``, the application code and any framework it uses
must be thread-safe.

**wsgi.multiprocess** — ``True`` if multiple processes may be
serving requests for the application. Daemon mode is multiprocess
when ``processes=N`` is set with ``N>1``, otherwise single-process.
Embedded mode is always multiprocess (each Apache child handles
requests independently). Application-state caches that need to be
shared across requests must allow for both ``multithread`` and
``multiprocess`` being ``True`` simultaneously.

**sys.version**, **sys.prefix**, **sys.path** — the Python
installation and module search path actually in use at runtime,
as discussed in the previous section.

Where to go next
----------------

* :doc:`installation-issues` — known build and runtime failure
  modes if any of the checks above point at a problem.
* :doc:`debugging-techniques` — broader debugging techniques for
  WSGI applications running under mod_wsgi.
* :doc:`configuration-issues` — common Apache configuration
  pitfalls.
