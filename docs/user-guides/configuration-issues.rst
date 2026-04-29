====================
Configuration Issues
====================

This page lists configuration-level problems that come up with mod_wsgi
under typical Linux distributions and Apache installations. Most are not
mod_wsgi bugs as such — they are interactions between mod_wsgi, Apache,
and the surrounding distribution defaults (filesystem permissions,
SELinux/AppArmor, restrictive Apache runtime directories, and so on).

If your problem is not covered here, also see :doc:`installation-issues`
and :doc:`application-issues`.

Apache server name warning
--------------------------

On a fresh Apache install, restarting Apache or running ``apachectl
configtest`` typically logs a line of the form::

    AH00558: Could not reliably determine the server's fully qualified \
     domain name, using 192.0.2.10. Set the 'ServerName' directive \
     globally to suppress this message

This warning is not specific to mod_wsgi — Apache emits it whenever it
cannot determine its own canonical server name from the host's DNS
configuration. The warning is harmless on its own, but the auto-detected
fallback ``ServerName`` may not match what you intended, which can affect
WSGI applications that read ``SERVER_NAME`` from the request environment
or that derive absolute URLs from it.

The fix is to declare ``ServerName`` explicitly at server scope::

    ServerName www.example.com

Or, for a host with no canonical public name, set it to a reasonable
local placeholder::

    ServerName localhost

Per-virtual-host ``ServerName`` declarations inside ``<VirtualHost>``
blocks do not suppress this warning — it is the global server scope that
needs the declaration.

File permissions on application files
-------------------------------------

The Apache user must be able to read the WSGI script file and every
directory between the filesystem root and the script. The same applies
to any Python modules imported by the application.

When the WSGI script lives under a user's home directory, the typical
home-directory mode of ``0700`` (Apache user has no traversal access)
or ``0755`` (read but not write) is the most common cause of mysterious
``500`` responses. Check the Apache error log for messages of the
form ``failed to import 'wsgi.py', exception was: PermissionError``
or, for the script file itself, ``not readable to Apache``.

The standard remedies are:

* Place the application directory and its contents in a location that
  is readable by the Apache user — typically under ``/var/www/`` or
  ``/srv/`` — rather than under a per-user home.
* If keeping the application under a home directory is required, grant
  the Apache user (or its group) read and traversal access via
  ``chgrp`` and ``chmod g+rx`` on the path components, or via ACLs
  (``setfacl``).
* When daemon mode is in use, consider running the daemon process as
  the application's owning user via the
  :doc:`../configuration-directives/WSGIDaemonProcess` ``user=`` and
  ``group=`` options. The daemon process runs as that user and reads
  the application files with that user's permissions, so the
  Apache-user permission constraint no longer applies — only the
  daemon-user constraint does.

Note that ``WSGIDaemonProcess user=``/``group=`` only takes effect when
Apache itself is started as ``root``; running as an unprivileged user
forces the daemon processes to run as that same user regardless of the
directive options.

Location of UNIX sockets
------------------------

When mod_wsgi is used in daemon mode, UNIX sockets are used to
communicate between the Apache child processes and the daemon
processes. These sockets and their associated mutex lock files are
placed in the standard Apache runtime directory by default — the same
directory that Apache log files are placed in.

Some Linux distributions apply restrictive permissions to that
directory such that it is not readable by other users. The Apache
child processes do not run as ``root`` and therefore cannot reach
inside the directory to connect to the sockets created by the daemon
processes. The result is a ``503 Service Temporarily Unavailable``
response back to the client and a message in the Apache error log
tagged with error code :ref:`WSGI0117`::

    (13)Permission denied: WSGI0117: Unable to connect to WSGI daemon \
     process '<group>' on '/etc/httpd/logs/wsgi.12345.0.1.sock' as \
     user with uid=33.

The fix is to relocate the sockets via the
:doc:`../configuration-directives/WSGISocketPrefix` directive. The
value may be relative to ``ServerRoot`` or absolute. Distributions
commonly provide a ``run`` directory inside the Apache root suitable
for module socket files::

    WSGISocketPrefix run/wsgi

On distributions such as RHEL/Fedora the per-server ``run`` directory
is itself locked down to ``root``-only access. In that case use the
operating-system-level ``/var/run`` instead::

    WSGISocketPrefix /var/run/wsgi

Do not place the sockets under ``/tmp``. ``/tmp`` is world-writable on
most systems, which exposes the socket file to spoofing or unlink
attacks by other users on the host. The directory used for the prefix
should only be writable by ``root`` (or by the user Apache is started
as, if Apache is not started as ``root``).

SELinux on RHEL and Fedora
--------------------------

On RHEL, CentOS Stream, AlmaLinux, Rocky Linux, and Fedora, SELinux is
enabled in enforcing mode by default. SELinux applies a set of policies
that restrict what Apache is allowed to do beyond what file-system
permissions alone permit. mod_wsgi running under such a policy can be
denied the ability to:

* Connect to its own daemon-process sockets.
* Read application script files placed outside Apache's expected
  document roots (anything not labelled ``httpd_sys_content_t`` or
  similar).
* Make outbound network connections to databases or upstream HTTP
  services from within the WSGI application.
* Bind to non-standard listen ports.

When SELinux denies an operation the Apache error log typically shows
a generic ``Permission denied`` even though the file-system permissions
are correct. The authoritative log of SELinux denials is the audit
log, ``/var/log/audit/audit.log``. The most useful query is for recent
``AVC`` (access vector cache) denials::

    sudo ausearch -m AVC -ts recent

For human-readable summaries with suggested remediation, install the
``setroubleshoot-server`` package and inspect ``journalctl`` after a
denial::

    sudo journalctl -t setroubleshoot

The standard remediations, in order of preference:

* **Set SELinux booleans** for whole categories of permission. The
  most commonly relevant for WSGI applications:

  * ``httpd_can_network_connect`` — allow Apache (and mod_wsgi) to
    make outbound network connections (databases, upstream APIs).
  * ``httpd_can_network_connect_db`` — narrower; just databases on
    standard ports.
  * ``httpd_can_sendmail`` — allow sending mail via the local MTA.

  Toggle via ``setsebool``, with ``-P`` to make the change persist
  across reboots::

      sudo setsebool -P httpd_can_network_connect on

* **Label application files** with an Apache-readable file context.
  For an application living outside ``/var/www/``::

      sudo semanage fcontext -a -t httpd_sys_content_t '/srv/myapp(/.*)?'
      sudo restorecon -R /srv/myapp

  Use ``httpd_sys_rw_content_t`` instead of ``httpd_sys_content_t`` if
  the application also needs to write — for example to maintain a
  cache directory.

* **Generate a custom policy** with ``audit2allow`` for one-off
  denials that no boolean covers::

      sudo ausearch -m AVC -ts recent | audit2allow -M mywsgi
      sudo semodule -i mywsgi.pp

  Review the generated ``mywsgi.te`` before installing — `audit2allow`
  builds the minimum policy that would have allowed the denied
  operations, but does not assess whether allowing them is wise.

* **Last-resort permissive mode** — useful only for diagnosis, never
  for permanent deployment. Switch the host to permissive mode
  temporarily, reproduce the failure, then read the audit log for the
  denials that would have occurred under enforcing::

      sudo setenforce 0

  Switch back to enforcing once you have identified the denials::

      sudo setenforce 1

  Permanent ``setenforce 0`` should be considered a configuration bug,
  not a fix.

AppArmor on Ubuntu
------------------

Ubuntu and other Debian derivatives may have AppArmor profiles in
effect for Apache. The default Ubuntu Apache packaging does not ship
an enforcing profile for ``apache2``, but if one has been added (by
a third-party package or by site policy) the symptoms can resemble
SELinux denials: ``Permission denied`` from operations whose
file-system permissions are correct.

Inspect the profile state with ``aa-status``::

    sudo aa-status

If a profile for ``apache2`` is loaded and in enforce mode, AppArmor
denials are logged via the kernel audit subsystem and visible in
``/var/log/syslog`` or ``/var/log/kern.log`` as ``apparmor="DENIED"``
entries. Adjusting the profile is a system-administration topic
beyond the scope of this page; consult the Ubuntu AppArmor
documentation.

WSGIDaemonProcess scoping
-------------------------

A :doc:`../configuration-directives/WSGIDaemonProcess` directive is
either at server (global) scope or inside a ``<VirtualHost>`` block.
The two forms behave differently and confusion between them is a
common source of "my virtual host can't find its daemon process group"
errors.

* When ``WSGIDaemonProcess`` is declared at server scope (outside any
  ``<VirtualHost>``), any virtual host on the server can delegate to
  that process group via ``WSGIProcessGroup``.

* When ``WSGIDaemonProcess`` is declared inside a ``<VirtualHost>``,
  only WSGI applications associated with that same virtual host (same
  ``ServerName``) can delegate to that process group. Other virtual
  hosts attempting to reference the group by name will fail with an
  Apache configuration error at startup.

Daemon process group names must be unique across the whole server.
Two virtual hosts each declaring ``WSGIDaemonProcess myapp ...`` is a
configuration error, regardless of where the directives appear.

When ``WSGIDaemonProcess`` is associated with a virtual host, the
mod_wsgi messages for that daemon group are written to the virtual
host's error log rather than to the main Apache error log. Always
check both logs when diagnosing daemon-process startup failures —
the relevant message may be in either, depending on whether the
declaration is at server or virtual-host scope.

**VirtualHost order matters when pre-loading via the script-alias
options.** The standalone ``WSGIProcessGroup`` directive stores its
name without validation; the named daemon group is resolved at
request time, by which point every ``WSGIDaemonProcess`` directive
in the configuration has been seen. Order of ``<VirtualHost>``
blocks therefore does not matter when ``WSGIProcessGroup`` is used.

The ``process-group=`` and ``application-group=`` *options* on
:doc:`../configuration-directives/WSGIScriptAlias`,
:doc:`../configuration-directives/WSGIScriptAliasMatch`,
:doc:`../configuration-directives/WSGIImportScript`, and
:doc:`../configuration-directives/WSGIDispatchScript` are different.
When both options are supplied as static values (no ``%{}``
expansion) the script becomes a candidate for pre-loading into the
daemon at startup, and mod_wsgi validates the named daemon group at
config-parse time. If the ``<VirtualHost>`` declaring the
``WSGIDaemonProcess`` has not yet been parsed when the reference is
encountered, Apache refuses to start with::

    WSGI process group not yet configured.

This bites in the common pattern of two virtual hosts sharing the
same ``ServerName`` on different ports (port 80 and port 443, for
example) where the daemon group is declared inside one of them and
the other references it. Place the ``<VirtualHost>`` that declares
``WSGIDaemonProcess`` before the one that references it via
``process-group=``, or move ``WSGIDaemonProcess`` to server scope
(outside any ``<VirtualHost>``) where order is irrelevant. Or, use
the standalone ``WSGIProcessGroup`` directive instead, which has no
config-parse-time ordering constraint at the cost of losing the
pre-loading benefit.

WSGIApplicationGroup and C extension modules
--------------------------------------------

By default each WSGI application runs in its own Python sub-interpreter
(application group). Some C extension modules — most prominently
NumPy, SciPy, and modules built on top of them — do not work correctly
in a sub-interpreter and assume they are running in the main Python
interpreter. The symptoms range from import errors at startup to
crashes and hangs once the C extension is exercised.

Set the application group to ``%{GLOBAL}`` to force the application to
run in the main interpreter::

    WSGIApplicationGroup %{GLOBAL}

This must be applied to every WSGI application that uses such an
extension, directly or transitively. Place the directive inside the
relevant ``<Directory>`` or ``<Location>`` block, or at virtual-host
scope if the whole site uses the extension.

The trade-off is that all applications running with
``WSGIApplicationGroup %{GLOBAL}`` share the same Python interpreter
and therefore the same Python module namespace. If you host multiple
WSGI applications on the same server and need them isolated from each
other (different versions of the same library, for instance), run
each one in its own daemon process group instead — daemon processes
each have their own main interpreter.

.htaccess directive limitations
-------------------------------

Not all mod_wsgi directives can be used inside a ``.htaccess`` file.
The ones that affect URL-to-script mapping (``WSGIScriptAlias``,
``WSGIScriptAliasMatch``) and process-model selection
(``WSGIDaemonProcess``, ``WSGIProcessGroup``) are server-config-only
and silently ineffective if placed in ``.htaccess`` — Apache will
not error, but the directive will not take effect.

The directives that *can* appear in ``.htaccess`` (subject to the
matching ``AllowOverride`` value being set on the parent directory)
are those that affect per-directory request processing:

* ``WSGIApplicationGroup``
* ``WSGIPassAuthorization``
* ``WSGIScriptReloading``
* ``WSGIChunkedRequest``
* ``WSGIErrorOverride``

Each directive page in :doc:`../configuration` lists its allowed
contexts and required override level under the ``Context`` and
``Override`` headings. The full directory-level configuration —
including ``WSGIScriptAlias`` — must live in the main Apache
configuration files.

RewriteRule and WSGIScriptAlias interaction
-------------------------------------------

When ``mod_rewrite`` rewrites a URL into a path that should be
handled by ``WSGIScriptAlias``, the ``[PT]`` (pass-through) flag is
required on the ``RewriteRule``. Without it the rewritten URL bypasses
the alias-resolution phase and the request is handed to Apache's
default file handler instead, typically resulting in a ``404`` or a
download of the WSGI script as a static file.

For example, to rewrite ``/legacy/...`` to be handled by the WSGI
application mounted at ``/app/...``::

    WSGIScriptAlias /app /usr/local/wsgi/scripts/myapp.wsgi

    RewriteEngine On
    RewriteRule ^/legacy/(.*)$ /app/$1 [PT,L]

The ``[PT]`` flag tells ``mod_rewrite`` to re-run the alias-resolution
phase on the rewritten URL so that ``WSGIScriptAlias`` matches.
``[L]`` ends rule processing once the rewrite happens. The same flag
combination is needed for any rewrite that targets a URL handled by
``WSGIScriptAlias``, ``WSGIScriptAliasMatch``, or any other alias-style
directive.

Restart versus graceful reload
------------------------------

Both ``apachectl graceful`` (``systemctl reload``) and
``apachectl restart`` cause the Apache parent process to re-read
the configuration. Module configuration phases run again, the MPM
generation number increments, and mod_wsgi daemon process groups
are shut down and respawned in either case. Configuration changes
to ``WSGIDaemonProcess`` options, ``WSGISocketPrefix``, and any
other directive that the daemon processes consume at startup take
effect under either form of restart.

The only difference between graceful and restart is at the Apache
child worker level:

* **Graceful** (``apachectl graceful``, ``systemctl reload``):
  existing Apache child worker processes are allowed to finish
  in-flight requests and honour any open ``Keep-Alive`` connections
  for up to ``GracefulShutdownTimeout`` (commonly 60 seconds)
  before being replaced. Clients see no interruption.

* **Restart** (``apachectl restart``): existing Apache child worker
  processes are terminated immediately. In-flight requests on those
  workers fail.

The daemon-process behaviour is identical under both. mod_wsgi
daemons are signalled to shut down so they can respawn under the
new configuration in either case. Apache provides no mechanism for
the "graceful" semantics it applies to its own child workers to
extend to externally managed processes, so a request already in
flight inside a daemon worker thread can be interrupted prematurely
under either form of restart. "Graceful" protects the Apache child
worker's keep-alive connection to the client, not the daemon
worker thread that may be partway through serving a request.

Graceful is still the better choice in almost every case, since it
preserves the Apache-side keep-alive connections that clients have
open at the moment the restart is issued. Just be aware that
long-running requests already being processed inside a daemon may
still be interrupted.

A side effect of graceful restart that can surface as recurring
``WSGI0116`` errors in the log is the daemon-process socket
rotation. By default mod_wsgi includes the MPM generation number
in the daemon socket path; when the generation increments on
graceful restart, Apache child workers still finishing
``Keep-Alive`` traffic try to connect to the previous generation's
socket and fail. See
:doc:`../configuration-directives/WSGISocketRotation` for the
workaround.

On both graceful reload and restart, Apache does call ``dlclose()``
on ``mod_wsgi.so`` and then ``dlopen()`` it again, so an upgraded
``mod_wsgi.so`` binary on disk does get picked up. The catch is
that ``dlclose()`` does not guarantee that the libraries the
module depended on are also unloaded from the process. Shared
libraries can be loaded with flags that explicitly prevent
unloading (``RTLD_NODELETE`` and platform equivalents), and they
may stay resident for other reasons besides — including being
referenced by another loaded library. The Python shared library
typically remains mapped for the life of the Apache parent
process once it has been loaded.

This matters when the upgrade also changes Python's major or
minor version (for example ``3.12`` → ``3.13``). The freshly
reloaded ``mod_wsgi.so`` is linked against the new
``libpython3.X.so``, but at runtime it resolves its Python symbols
against whichever ``libpython`` is already resident in the
process — that is, the *older* version that did not unload. The
result is undefined behaviour or outright crashes.

To avoid this, fully stop and start Apache (``apachectl stop``
followed by ``apachectl start``) when upgrading mod_wsgi or
upgrading Python. Stopping the parent process unloads everything;
the new parent then loads ``mod_wsgi.so`` and the matching
``libpython`` fresh.

For changes within the WSGI application itself — Python code,
imported modules, configuration files read by the application —
neither a graceful reload, restart, nor full Apache stop/start is
required. ``touch``-ing the WSGI script file causes the daemon
process group to recycle on the next request, picking up the new
code.
