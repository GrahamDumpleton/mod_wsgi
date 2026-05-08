====================
Security Hardening
====================

This page covers operational hardening of mod_wsgi deployments:
running with least privilege, isolating application components
from each other, controlling filesystem access, and limiting
exposure to common classes of attack on the Apache and mod_wsgi
layer.

Material covered elsewhere is not duplicated here:

* Reporting security issues, supported version policy, and the
  list of past CVEs are in :doc:`../security-issues`.
* TLS termination, certificate handling, HSTS, and client
  certificate (mTLS) authentication are in :doc:`enabling-https`.
* Trusted-proxy header configuration is in
  :doc:`running-behind-a-reverse-proxy`.

Application-level web security (input validation, output
encoding, CSRF, SQL injection, secret management, and so on)
is the responsibility of the WSGI application itself and is
out of scope for this page.

Choose daemon mode
------------------

mod_wsgi can host a WSGI application in two modes. Embedded
mode loads the application directly into Apache's child worker
processes; daemon mode runs the application in separate
processes that Apache forwards requests to. For any deployment
where security matters, use daemon mode.

The differences that matter for security:

* Daemon-mode processes can run as a dedicated unprivileged
  user separate from the Apache user. On a system Apache this
  is configured via ``user=`` / ``group=`` on
  ``WSGIDaemonProcess``; with ``mod_wsgi-express`` the
  recommended pattern is to start the express instance as the
  dedicated user from the outset (see below). Embedded mode
  runs as whatever user Apache itself runs as, which on a
  system Apache is typically shared with mod_php, static-file
  serving, and any other Apache modules.
* Daemon-mode processes have their own address space. A bug or
  exploit in the WSGI application affects only the daemon
  process pool, not Apache's child workers, and not other
  applications hosted by the same Apache.
* Daemon-mode processes can be recycled on a schedule and
  individually killed without restarting Apache. Resource
  limits (RLIMIT_AS, RLIMIT_CPU, etc.) apply per-process.
* Daemon-mode processes have their own Python interpreter
  state. In embedded mode the interpreter is shared with the
  Apache worker pool and survives across requests in
  potentially surprising ways.

To make daemon-only deployment a hard requirement and prevent
a misconfiguration from accidentally placing the application
into embedded mode, set::

    WSGIRestrictEmbedded On

The Apache worker processes will then refuse to load any WSGI
application that has not been explicitly directed into a
daemon process group.

Run as a dedicated unprivileged user
------------------------------------

The daemon process pool should run as an unprivileged service
account that exists for the sole purpose of running this
application. On a system Apache::

    WSGIDaemonProcess example processes=2 threads=15 \
        user=example-app group=example-app
    WSGIProcessGroup example

The Apache parent process needs root to bind privileged ports
and to fork the daemon, but the daemon itself drops privileges
to ``example-app`` before serving requests. When ``user=`` and
``group=`` are not specified, the daemon runs as Apache's
default unprivileged user (``www-data`` on Debian/Ubuntu,
``apache`` on RHEL/Fedora, ``nobody`` on some other
distributions), which is shared with the rest of Apache on the
host. Always set ``user=`` and ``group=`` to a dedicated
service account.

With ``mod_wsgi-express`` the recommended pattern is different:
start the express instance directly as the dedicated user, on
an unprivileged port, with a separate reverse proxy or ingress
in front to bind the privileged ports and terminate TLS. There
is no need to start as root because there is no privileged port
to bind. Under systemd this is a ``User=example-app`` line in
the unit file; in a container it is the ``USER`` directive in
the Dockerfile (see :doc:`installing-with-docker`); from a
shell it is ``sudo -u example-app``::

    sudo -u example-app mod_wsgi-express start-server wsgi.py \
        --host 127.0.0.1 --port 8000 \
        --log-to-terminal

The ``--user`` and ``--group`` options to ``mod_wsgi-express``
exist for the alternate pattern where the express instance is
itself binding a privileged port (typically because it is the
front-line server with no proxy in front of it). It then needs
to be started as root and drop privileges before serving
requests::

    sudo mod_wsgi-express start-server wsgi.py \
        --port=80 --user example-app --group example-app

For most production deployments the proxy-front-end pattern is
preferred and ``--user`` / ``--group`` are not needed; see
:doc:`running-behind-a-reverse-proxy` and
:doc:`enabling-https` for the front-end side, and
:doc:`mod-wsgi-express-quickstart` for the
privileged-port flow.

The choice of account matters in either case:

* Do not run as ``root``. The Apache parent process needs root
  to bind privileged ports and to fork the daemon, but the
  daemon itself drops privileges. Never set ``user=root`` or
  similar.
* Do not reuse the Apache user (``www-data``, ``apache``,
  ``http``). That account is shared with static-file serving,
  ``mod_php``, ``mod_perl``, and any other Apache module on
  the host. A bug in the WSGI application then has access to
  whatever the Apache user has access to.
* Do not use ``nobody``. It is a default fallback account
  shared between unrelated services on most distributions.
* Create a fresh service account per application. The
  conventional name is the application's name with an ``-app``
  suffix.

Make sure the daemon user has the minimum filesystem access
needed to run the application. See "Filesystem hardening"
below.

Isolate application components from each other
-----------------------------------------------

A single Apache instance often hosts more than one WSGI
application: an admin interface, a public website, an internal
API, a billing component. mod_wsgi can run each of these in a
separate daemon process pool, with a separate user account,
and with the routing fenced so that requests destined for one
component cannot accidentally end up handled by another.

The pieces that combine to give per-component isolation:

* One ``WSGIDaemonProcess`` per component, each with its own
  ``user=`` and ``group=``.
* One ``WSGIProcessGroup`` per ``<VirtualHost>`` (or
  ``<Location>``) to route requests to the right pool.
* ``WSGIApplicationGroup %{GLOBAL}`` so each pool runs its
  application in its own main interpreter rather than a
  sub-interpreter (sub-interpreter isolation has known limits
  with C extensions and is not a security boundary; see
  :doc:`processes-and-threading`).
* ``WSGIRestrictProcess`` on each ``<VirtualHost>`` listing
  only the process-group name that vhost is allowed to use.
  This prevents a misconfiguration (a typo in a
  ``WSGIProcessGroup`` line, an ``.htaccess`` rule that names a
  different pool, an upload-controlled WSGI file dropped into
  the wrong directory) from routing requests into another
  component's daemon.

A worked example with three components of the same system,
hosted by one Apache instance::

    WSGIDaemonProcess admin-app processes=1 threads=15 \
        user=admin-app group=admin-app
    WSGIDaemonProcess public-app processes=2 threads=15 \
        user=public-app group=public-app
    WSGIDaemonProcess api-app processes=2 threads=15 \
        user=api-app group=api-app

    <VirtualHost *:443>
        ServerName admin.example.com

        SSLEngine on
        SSLCertificateFile    /etc/pki/example/admin.crt
        SSLCertificateKeyFile /etc/pki/example/admin.key

        WSGIProcessGroup       admin-app
        WSGIApplicationGroup   %{GLOBAL}
        WSGIScriptAlias / /var/www/admin/wsgi.py

        WSGIRestrictProcess admin-app

        <Directory /var/www/admin>
            Require all granted
        </Directory>
    </VirtualHost>

    <VirtualHost *:443>
        ServerName www.example.com

        SSLEngine on
        SSLCertificateFile    /etc/pki/example/public.crt
        SSLCertificateKeyFile /etc/pki/example/public.key

        WSGIProcessGroup       public-app
        WSGIApplicationGroup   %{GLOBAL}
        WSGIScriptAlias / /var/www/public/wsgi.py

        WSGIRestrictProcess public-app

        <Directory /var/www/public>
            Require all granted
        </Directory>
    </VirtualHost>

    <VirtualHost *:443>
        ServerName api.example.com

        SSLEngine on
        SSLCertificateFile    /etc/pki/example/api.crt
        SSLCertificateKeyFile /etc/pki/example/api.key

        WSGIProcessGroup       api-app
        WSGIApplicationGroup   %{GLOBAL}
        WSGIScriptAlias / /var/www/api/wsgi.py

        WSGIRestrictProcess api-app

        <Directory /var/www/api>
            Require all granted
        </Directory>
    </VirtualHost>

A bug or exploit in the public site's code now runs as
``public-app``, can read and write only the files that user
has access to, and cannot signal, ``ptrace``, or otherwise
interfere with the ``admin-app`` or ``api-app`` daemon
processes (each running with a different effective UID, in its
own address space). ``WSGIRestrictProcess`` makes the routing
intent explicit: a request that arrives in the
``api.example.com`` vhost is only allowed to dispatch into the
``api-app`` daemon, regardless of what any nested
``WSGIProcessGroup`` directive might say.

**Use a separate Python virtual environment per component.**

Beyond running each component as its own process and user,
give each component its own Python virtual environment.
Sharing a virtualenv across unrelated applications means a
package update for one of them changes the runtime for all
the others in the same shared environment, so an upgrade of
(say) ``cryptography`` for the API also silently bumps it for
the public site, and a regression in the new release affects
every component using that environment. Isolated virtualenvs
let each component be tested and rolled forward on its own
schedule, and let pre-rollout validation against a single
component happen without affecting the others.

Point each daemon at its own virtualenv with the
``python-home=`` option on ``WSGIDaemonProcess``::

    WSGIDaemonProcess admin-app processes=1 threads=15 \
        user=admin-app group=admin-app \
        display-name=%{GROUP} \
        python-home=/var/lib/admin-app/venv
    WSGIDaemonProcess public-app processes=2 threads=15 \
        user=public-app group=public-app \
        display-name=%{GROUP} \
        python-home=/var/lib/public-app/venv
    WSGIDaemonProcess api-app processes=2 threads=15 \
        user=api-app group=api-app \
        display-name=%{GROUP} \
        python-home=/var/lib/api-app/venv

For embedded mode (which security-sensitive deployments
should not be using; see "Choose daemon mode" above), the
equivalent is the server-scoped ``WSGIPythonHome`` directive.
Embedded mode supports only one virtualenv across all
applications hosted in the Apache instance, which is one of
several reasons it is unsuitable for multi-component
deployments.

This pattern works well when the components are parts of the
same overall system run by a single operator. **Sharing an
Apache instance across unrelated parties is a different
matter.** Hosting WSGI applications belonging to different
customers, organisations, or untrusted users on a single
Apache process tree is not advisable for any deployment where
the parties are not part of the same trust boundary. Even with
``WSGIRestrictProcess`` and per-component users, the parties
share the parent Apache process, the configuration file (which
typically only one party can edit), the ``LogLevel`` and other
server-wide settings, the Apache error log, and the host's
network and filesystem. A Apache or mod_wsgi vulnerability,
or a misconfiguration, has cross-tenant blast radius.

The recommended pattern for hosting unrelated parties is to
give each its own Apache instance (or its own
``mod_wsgi-express`` instance, or its own container, or its
own host) behind a shared front-line reverse proxy that routes
by hostname. Sharing one Apache instance across unrelated
users is reasonable only for non-critical systems where the
blast radius of a cross-tenant incident is acceptable: shared
sandboxes, learning environments, internal scratch hosts.

**Make daemon processes identifiable in ps and top.**

By default, daemon processes retain Apache's ``argv[0]`` and
appear as ``httpd`` or ``apache2`` in ``ps``, ``top``, and
``htop`` output, indistinguishable from Apache's own child
worker processes. In a multi-component deployment this makes
identifying which processes belong to which application pool
unnecessarily difficult, both during day-to-day operations
(``pgrep``, ``kill``, monitoring) and during incident
response.

Set the ``display-name=`` option on each ``WSGIDaemonProcess``
to a distinctive name::

    WSGIDaemonProcess admin-app processes=1 threads=15 \
        user=admin-app group=admin-app \
        display-name=%{GROUP}
    WSGIDaemonProcess public-app processes=2 threads=15 \
        user=public-app group=public-app \
        display-name=%{GROUP}
    WSGIDaemonProcess api-app processes=2 threads=15 \
        user=api-app group=api-app \
        display-name=%{GROUP}

When ``display-name=`` is set to the literal token
``%{GROUP}`` mod_wsgi substitutes the daemon process group's
name and wraps it in a ``(wsgi:...)`` form. The three pools
above appear in ``ps`` as ``(wsgi:admin-app)``,
``(wsgi:public-app)``, and ``(wsgi:api-app)`` respectively
(the parentheses and the ``wsgi:`` prefix are added by
mod_wsgi automatically; the prefix marks the processes as
mod_wsgi daemons, distinguishing them from Apache's own child
worker processes). Operations that target a specific pool
(``pgrep wsgi:public-app``, monitoring filters,
log-collection rules) become unambiguous.

**Restarting a single application pool with a signal.**

The same naming makes it possible to send signals to one
component's daemon processes without touching the rest of
Apache. mod_wsgi handles Apache's graceful restart signal
(``SIGUSR1`` on UNIX) on a daemon by stopping new request
acceptance, waiting for in-flight requests to finish,
exiting, and being replaced by a fresh process forked by the
Apache parent. The fresh process re-loads the application,
picking up code or virtualenv changes since the previous
start. To trigger this for just one pool::

    pkill -USR1 -f wsgi:public-app

The ``admin-app`` and ``api-app`` daemons are not affected.

Set ``graceful-timeout=`` on ``WSGIDaemonProcess`` to bound
how long the restart waits for active requests to complete
before they are forcibly interrupted. Without a
``graceful-timeout=`` value the restart proceeds immediately
and any in-flight request is dropped. ``eviction-timeout=``
can be used in addition to ``graceful-timeout=`` to control
the timing more precisely when the graceful restart signal
is the trigger; see the
:doc:`../configuration-directives/WSGIDaemonProcess` directive
page for the full timeout chain.

``SIGUSR1`` is not the only way to recycle a daemon pool.
With ``WSGIScriptReloading`` left at its default of ``On``,
mod_wsgi also recycles the daemon when the file pointed at by
``WSGIScriptAlias`` is modified. With the recommended
filesystem layout (the small WSGI script file kept separate
from the project code; see "Separate the WSGI script file
from the project code" below), touching that file is always
a deliberate operator action rather than an incidental
side-effect of a project source-code update. For deployments
that prefer fully signal-driven control with no implicit
file-mtime trigger, set ``WSGIScriptReloading Off`` and
recycle exclusively with ``pkill -USR1``.

This is useful for workflows where reloading a single
component is the right granularity (deploying a code change
to one app on a host shared with others, exercising a
restart in development). It is not by itself a deployment
process for production.

Filesystem hardening
--------------------

The daemon process should have read access to the application
code and write access to a small, well-defined set of
directories, and nothing else.

**Keep project code outside the document root.**

Place the application's source code in a directory that is
not under the Apache ``DocumentRoot`` (for system Apache) or
the directory served by ``--document-root`` (for
``mod_wsgi-express``). Conventional locations are
``/var/lib/<app>``, ``/opt/<app>``, or a directory under the
deployment user's home. Avoid placing the project under
``/var/www``, ``/srv``, or any other directory that is
configured as a document root.

The risk with project code under the document root is that a
misconfiguration leaks it as plain text. If the
``WSGIScriptAlias`` directive is removed, commented out for
testing, or its handler binding broken (an ``AddHandler``
change, an ``.htaccess`` typo, an Apache module reorder),
Apache will fall back to serving the ``.py`` files as static
files. Source code, configuration constants, and any
credentials embedded in the code then become directly
downloadable. Project code that lives somewhere
``DocumentRoot`` does not point at avoids the situation
entirely.

**Separate the WSGI script file from the project code.**

The file referenced by ``WSGIScriptAlias`` is opened during
request handling. Apache child worker processes (running as
``www-data`` / ``apache`` / similar) need search permission on
every directory along the path to that file. If the project
code directory is owned by the daemon user with restrictive
permissions (mode ``0700`` for example), the Apache child
worker user cannot traverse into it and ``WSGIScriptAlias``
resolution fails.

The recommended layout puts just the small ``.wsgi`` /
``.py`` entry-point file in a separate, Apache-traversable
directory while the project code itself lives somewhere with
tighter permissions::

    /var/www/example/wsgi.py        # Apache-traversable entry point
    /var/lib/example-app/...        # project code, locked-down ownership

The entry-point file does nothing more than import the actual
application from the project::

    from example_app.wsgi import application

The entry-point's parent directory (``/var/www/example`` in
this layout) is configured to be traversable by the Apache
user, so ``WSGIScriptAlias`` resolution succeeds. The project
code directory (``/var/lib/example-app``) only needs to be
accessible to the daemon user, since the daemon process is the
one that actually loads the imported modules.

**Set the daemon's working directory.**

By default the daemon process inherits its current working
directory from the Apache parent, which on a system Apache is
typically the filesystem root (``/``). Application code that
opens files by relative path resolves those paths against
``/``, which is almost never what the application intends. Set
the working directory explicitly with the ``home=`` option on
``WSGIDaemonProcess``::

    WSGIDaemonProcess example processes=2 threads=15 \
        user=example-app group=example-app \
        home=/var/lib/example-app

The directory specified with ``home=`` is also added to the
daemon's ``sys.path``, so modules in the project become
importable without an additional ``WSGIPythonPath``
configuration.

For ``mod_wsgi-express`` the equivalent is
``--working-directory``::

    sudo -u example-app mod_wsgi-express start-server wsgi.py \
        --working-directory /var/lib/example-app

Without ``--working-directory`` the express instance defaults
to the directory the express command was run from, which can
end up being a surprising value (the user's home, the
directory ``systemd`` placed the unit in, the directory
``cron`` ran the job from). Set it explicitly.

**Application code ownership and permissions.**

* Owned by the deployment user (the account that performs
  ``git pull`` / ``rsync`` / ``pip install`` to lay down the
  code), not by the daemon user.
* Readable but not writable by the daemon user (group-readable
  with the daemon user as a group member, or world-readable if
  the code contains no secrets).
* The WSGI script file specifically should be a single file
  pointed at by ``WSGIScriptAlias``, not a directory under
  which any ``.wsgi`` or ``.py`` file would be picked up.
  Mounting a directory makes it possible for an upload bug or
  an unrelated misconfiguration (cron-based file generation,
  log rotation creating files in the wrong place) to drop a
  file that becomes executable as the daemon user.

**Writable directories** (uploads, caches, session files,
application logs):

* Owned by and writable by the daemon user.
* Located outside the document root and outside any directory
  configured as a ``WSGIScriptAlias`` target.
* Not under ``/tmp``. ``/tmp`` is world-writable and shared with
  every other process on the host; it is straightforward for
  an unrelated process to predict or race filenames there.
  Use a dedicated directory under ``/var/lib/<app>`` or under
  the daemon user's home directory.

**Granting access to files owned by other users.**

When the application needs to read or write files owned by a
different user (a database UNIX socket directory, a shared
log directory, content placed there by another service),
prefer the most specific grant of access:

* Do not work around the problem by making the files
  world-readable or world-writable. The leak extends to every
  local user and every process on the host.
* Do not add the daemon user to a system group permanently
  via ``usermod -aG``. The grant then applies to every
  process the daemon user runs (cron jobs, debugging shells,
  ad-hoc utilities), not just the WSGI application.
* Use the ``supplementary-groups=`` option on
  ``WSGIDaemonProcess`` to add the additional group(s) only
  to the daemon process at start time. The system user's
  group membership in ``/etc/group`` is unchanged; only the
  mod_wsgi daemon picks up the extra group::

      WSGIDaemonProcess example processes=2 threads=15 \
          user=example-app group=example-app \
          supplementary-groups=postgres

  This keeps the access scoped to the daemon process and
  documents the grant in the Apache configuration where it
  is discoverable.

For per-file or per-directory grants that do not fit a
group-based model, POSIX ACLs (``setfacl`` / ``getfacl``)
are the next step up. ACLs are precise but less discoverable
(an ACL is shown only as a ``+`` after the mode in
``ls -l``; you have to ``getfacl`` to see the contents),
require the filesystem to be mounted with ACL support, and
are not preserved by every backup tool. Reach for ACLs when
the access is to a small handful of specific files and
modelling it as a group is awkward.

**The WSGI daemon socket directory:**

* ``WSGISocketPrefix`` controls where mod_wsgi creates the
  UNIX domain sockets that Apache child workers use to talk to
  daemon-mode processes. The directory must be writable by the
  Apache parent process (which creates the sockets) and
  readable / connect-accessible by the Apache child workers
  (which open them).
* On Apache distributions that include a system-wide socket
  directory (``/var/run/apache2/`` and similar), prefer that
  over a path under ``/tmp``. ``WSGISocketPrefix`` is commonly
  set to a path under that system directory.
* Sockets are created with restrictive permissions by default.
  Do not loosen the daemon socket directory's permissions
  beyond what the Apache user requires.

**Tightening the daemon's umask:**

The ``umask=`` option on ``WSGIDaemonProcess`` controls the
default file mode for files the application creates::

    WSGIDaemonProcess example processes=2 threads=15 \
        user=example-app group=example-app umask=0027

A ``umask`` of ``0027`` makes new files unreadable by other
users on the host (group-readable only). Setting this guards
against an application bug that creates a file in a shared
directory with too-permissive defaults.

**Optional script-file ownership validation:**

The ``script-user=`` and ``script-group=`` options on
``WSGIDaemonProcess`` cause mod_wsgi to verify that the WSGI
script file is owned by the named user / group before loading
it::

    WSGIDaemonProcess example processes=2 threads=15 \
        user=example-app group=example-app \
        script-user=root script-group=root

A request that lands on a script file with the wrong ownership
fails rather than executing untrusted code. This is a cheap
check worth adding when the deployment process can guarantee
the script file's ownership.

Network exposure
----------------

When ``mod_wsgi-express`` runs behind a reverse proxy or
ingress controller, the back-end should not be reachable
directly from outside that proxy. Bind to the loopback
interface explicitly::

    mod_wsgi-express start-server wsgi.py \
        --host 127.0.0.1 --port 8000 \
        ...

A back-end bound only to ``127.0.0.1`` cannot be reached from
the network even if the host's firewall is misconfigured. For
a containerised back-end, the equivalent is the container's
private network namespace plus whatever ingress controller
exposes the service.

For the matching trusted-proxy and TLS-termination
configuration, see :doc:`running-behind-a-reverse-proxy` and
:doc:`enabling-https`.

Authentication
--------------

``WSGIPassAuthorization`` controls whether the
``Authorization`` (and ``Proxy-Authorization``) HTTP request
headers are passed through to the WSGI application. The
default is ``Off``: the headers are stripped before the
application sees them.

* Leave the default ``Off`` for any application that does not
  itself process the ``Authorization`` header. Apache auth
  modules (``mod_auth_basic``, ``mod_auth_digest``,
  ``mod_authnz_ldap``, ``mod_auth_openidc``, etc.) consume the
  header at the Apache layer and the application sees only the
  authenticated ``REMOTE_USER`` after the fact.
* Set ``WSGIPassAuthorization On`` only when the application
  explicitly handles the header (REST APIs that authenticate
  via ``Bearer`` tokens, applications that manage HTTP Basic
  authentication themselves). Be aware that anything the
  application does with the header (logging, debug-page
  rendering, error reporting to a third-party service)
  potentially exposes credentials.

Trusted proxy headers (``X-Forwarded-For``,
``X-Forwarded-Proto``, etc.) are not authentication
credentials. They are how the back-end learns the original
client's IP, host, and protocol scheme; the trust comes from
``WSGITrustedProxies`` listing the IP addresses requests are
allowed to arrive from. Without that list, any client can
spoof the headers. See :doc:`running-behind-a-reverse-proxy`
for the details.

Resource limits and DoS resistance
----------------------------------

mod_wsgi exposes a number of timeouts and recycling triggers
on ``WSGIDaemonProcess`` that protect against memory leaks,
hung requests, and slow-client / resource-exhaustion attacks
at the application layer:

* ``maximum-requests`` recycles the daemon process after a set
  number of requests, limiting the impact of leaks.
* ``inactivity-timeout`` and ``cpu-time-limit`` recycle on
  resource-use thresholds.
* ``request-timeout`` and ``interrupt-timeout`` bound how long
  a single request may take before mod_wsgi stops waiting and
  recycles the worker thread.
* ``graceful-timeout`` and ``shutdown-timeout`` bound the
  in-flight wait when daemon processes are restarting.

See the :doc:`../configuration-directives/WSGIDaemonProcess`
directive page for the full set of options and the recycling
model.

At the Apache layer, the directives that bound resource use
across the connection layer are independent of mod_wsgi:

* ``LimitRequestBody`` caps the size of a request body Apache
  will accept before invoking mod_wsgi.
* ``LimitRequestFields`` and ``LimitRequestFieldSize`` cap the
  number and individual size of request headers.
* ``RequestReadTimeout`` (from ``mod_reqtimeout``) caps how
  long Apache will wait for a slow client to send the request
  headers and body, mitigating slowloris-style attacks.

Information disclosure
----------------------

By default Apache and mod_wsgi can reveal more about the host
than an internet-facing deployment ought to expose:

* Apache emits the server version and operating system in the
  ``Server:`` response header and at the bottom of error pages.
  Set ``ServerTokens Prod`` and ``ServerSignature Off`` in the
  Apache configuration to suppress this.
* Default Apache error pages contain the request URI, the
  server hostname, and sometimes other internal detail.
  Configure ``ErrorDocument`` for the common 4xx and 5xx
  status codes to serve fixed pages that do not echo
  request-specific data.
* In production, ``LogLevel warn`` is the appropriate baseline
  for the WSGI application; verbose levels (``info``, ``debug``,
  ``trace1`` and below) emit request-level information into
  the Apache error log that may include URIs, headers, or
  application traces. ``LogLevel warn wsgi:info`` is a
  reasonable middle ground when mod_wsgi diagnostic detail is
  needed without raising Apache as a whole.
* WSGI framework debug pages (``DEBUG=True`` settings,
  Werkzeug debugger, Django technical-500 page) leak source
  code, environment variables, and sometimes secrets. Make
  sure these are unreachable from production traffic; do not
  rely on the application alone to gate them.

What the code already handles
-----------------------------

Some attack-surface mitigations are built into the mod_wsgi
code rather than being settings the operator configures:

* The HTTP ``Proxy:`` request header is unconditionally
  stripped from the environment before the WSGI application
  is invoked, mitigating the httpoxy class of attack
  (`CVE-2016-5388 <https://httpoxy.org/>`_). Applications that
  consult ``HTTP_PROXY`` for outbound proxy configuration are
  not influenced by request-supplied values.
* Pass-through of the ``Authorization`` and
  ``Proxy-Authorization`` request headers to subordinate
  handlers is gated by Apache's ``CGIPassAuth`` directive (the
  default off; see "Authentication" above).
* When ``WSGITrustedProxies`` and ``WSGITrustedProxyHeaders``
  are configured, mod_wsgi strips synonym headers in any
  declared category from the WSGI environment when a request
  arrives from a non-trusted peer, so an attacker cannot spoof
  ``X-Real-IP`` past a configuration that trusts only
  ``X-Forwarded-For``. See
  :doc:`running-behind-a-reverse-proxy` for the details.

These do not require operator configuration; they are the
default behaviour of current mod_wsgi.

Where to go next
----------------

* :doc:`../security-issues` for reporting a security issue,
  the supported version policy, and the list of past CVEs.
* :doc:`enabling-https` for TLS termination, HSTS, and client
  certificate (mTLS) authentication.
* :doc:`running-behind-a-reverse-proxy` for trusted-proxy
  header configuration and the corresponding front-end proxy
  setup.
* :doc:`processes-and-threading` for the daemon-mode process
  model in depth.
* :doc:`../configuration-directives/WSGIDaemonProcess`,
  :doc:`../configuration-directives/WSGIRestrictEmbedded`, and
  :doc:`../configuration-directives/WSGIRestrictProcess` for
  the directive-level reference of the knobs touched by this
  page.
