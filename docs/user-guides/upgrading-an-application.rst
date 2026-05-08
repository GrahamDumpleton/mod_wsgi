========================
Upgrading An Application
========================

This guide covers patterns for upgrading the code or dependencies of
a running mod_wsgi-served application with as little downtime as
possible, and with a clear path back to the previous version if the
new release misbehaves.

Where This Guide Fits
---------------------

The cleanest way to do a zero-downtime upgrade is at the
*infrastructure* layer: run the old and new versions of the
application as separate hosts, separate containers, or separate
Kubernetes ``Deployment`` objects, and shift traffic between them at
the load balancer, service mesh, or ``Service`` / ``Ingress`` layer.
The two versions don't share an Apache; the old one stays untouched
until you cut it off; rollback is a load-balancer change. When that
option is on the table, take it.

This guide covers the case where it isn't: one Apache instance hosts
the application, and the upgrade has to happen *within* that single
instance. That's the typical situation for a system-package install
on a single host, a small fleet behind a simple front end, or a
long-lived deployment where standing up parallel instances isn't
proportionate to the change being shipped.

The patterns below allow the cutover to happen without restarting
Apache, and most of them allow rollback without a redeploy.

Why In-Place File Replacement Isn't Enough
-------------------------------------------

Replacing application files in place while the daemon processes are
running has two failure modes that motivate the more careful
patterns in the rest of this guide:

* **Half-applied state.** Python caches modules in ``sys.modules``
  for the lifetime of the interpreter. If a worker imports half of
  the new release before the rest of the files have been written,
  it can see a mismatched mix of old and new code and crash mid
  request.
* **Shared virtualenv churn.** Upgrading a package in the
  application's virtualenv affects every running process that
  already imported the previous version of that package. There is
  no way to swap a package version under a running interpreter.

The patterns in this guide all give you an *atomic* switch from old
to new code, and most of them keep the previous version available
for fast rollback.

A Note On Mixed-Version Request Handling
-----------------------------------------

Several patterns in this guide have a window during which some
requests are served by the old version and others by the new. The
graceful-drain SIGUSR1 cutover described below keeps the old
daemon serving in-flight and newly-arriving requests until idle
while a recycled daemon also accepts traffic; the percentage and
sticky canary forms of the dispatch script explicitly mix traffic
across versions by design; even hard cutovers between parallel
daemon process groups have a brief overlap as in-flight requests
in the old group drain after the routing change.

This is fine when the two versions are compatible for concurrent
execution. It is *not* fine when, for example, one version writes
cache entries, queued jobs, or session state in a shape the other
can't read; the two expect different request or response shapes
at an API boundary with their callers; or schema migrations
require columns one version doesn't yet write or the other has
stopped using.

For incompatible upgrades, the right answer is to make the
versions compatible for concurrent execution first. Stage the
change as two or more deploys, each backwards-compatible with the
previous: ship the new code with both old and new behaviour
available, validate, then a later deploy removes the old
behaviour. The Database Schema Considerations section later in
this guide walks through that pattern for schema changes; the
same idea applies to API shapes, cache formats, and any other
cross-version coupling.

If the change can't be staged that way, the only option is to
stop accepting traffic at the load balancer, wait for in-flight
requests to drain, then bring the new version up. That costs a
short outage in exchange for a clean version boundary.

Strategies At A Glance
----------------------

The patterns form a ladder. Each rung offers more rollback capability
and more overlap, at the cost of more configuration work and more
resource use:

* **Atomic code-root swap.** Single daemon process group, but each
  release lives in its own dated directory with its own
  virtualenv, selected via a ``current`` symlink. Flip the symlink
  atomically and recycle. Handles dependency changes; no overlap
  window for rollback.
* **Version selection inside the WSGI script.** Single daemon
  process group, but the WSGI script chooses which version's code
  and virtualenv to load. Cutover edits one file. No Apache config
  change needed; works in environments where you can't add new
  daemon process group declarations.
* **Parallel daemon process groups.** Declare two persistent
  daemon process groups (typically named blue/green) and
  alternate between them across deploys. Each owns its own
  virtualenv. The cutover is purely a routing change. Rollback is
  instant because the previously-live side is still warm. This is
  the canonical single-instance pattern.

The remainder of this guide describes each rung, plus the two
mechanisms (a dispatch script, or a ``mod_rewrite`` map file) that
drive the switch when parallel process groups are in play.

Atomic Code-Root Swap
---------------------

When you don't need a warm overlap or per-request canary routing,
the simplest atomic pattern is the Capistrano-style symlink swap:
each release goes into its own dated directory, and a single
``current`` symlink selects the live one. Because POSIX
``rename(2)`` is atomic for one filesystem entry, retargeting the
symlink with a single rename is a true tree-level swap. Per-file
rename sequences (whether by hand or via ``rsync
--delay-updates``) are not atomic at the tree level: an
application that reads files at request time can see a
half-applied state during the rename window.

The on-disk layout is one directory per release, each containing
both the code and the virtualenv, with a single ``current``
symlink that selects the live release::

    /srv/myapp/releases/2026-05-08-12-34/code/
    /srv/myapp/releases/2026-05-08-12-34/venv/
    /srv/myapp/releases/2026-05-09-09-15/code/
    /srv/myapp/releases/2026-05-09-09-15/venv/
    /srv/myapp/current -> releases/2026-05-09-09-15

The Apache configuration refers to ``/srv/myapp/current``
everywhere the application's filesystem layout is named::

    WSGIDaemonProcess app processes=4 threads=15 \
        user=appsvc group=appsvc \
        python-home=/srv/myapp/current/venv \
        home=/srv/myapp/current/code \
        display-name=%{GROUP}

    WSGIScriptAlias / /srv/myapp/current/code/myapp.wsgi \
        process-group=app application-group=%{GLOBAL}

``python-home=``, ``home=``, and the script path all resolve
through the ``current`` symlink, so flipping the symlink switches
code, virtualenv, and everything else resolved beneath it.

The cutover is two atomic steps. First, build the new release
fully in its own directory (code, virtualenv, dependencies, any
generated assets) and verify it. Then flip the symlink::

    ln -sfn /srv/myapp/releases/NEW /srv/myapp/current.tmp
    mv -T /srv/myapp/current.tmp /srv/myapp/current

``ln -sfn`` writes the new symlink under a temporary name; ``mv
-T`` (``--no-target-directory``) renames it atomically over the
existing ``current`` symlink in a single ``rename(2)`` call.
After the swap, ``/srv/myapp/current/code/myapp.wsgi`` resolves
to a different file on disk than it did before. When mod_wsgi
next stats the script path, the kernel returns that new file's
modification time, which differs from the previous file's
cached mtime, and mod_wsgi treats the difference as a script
change and recycles the daemon process group. The recycled
interpreter sees the new code and the new virtualenv via the
kernel's symlink resolution.

If the new release's WSGI script happens to share its mtime
with the previous release's (for example, a reproducible-build
pipeline that normalises timestamps), the recycle won't trigger
automatically. In that case, ``touch
/srv/myapp/current/code/myapp.wsgi`` after the symlink swap to
force the change.

The mtime-detection recycle path goes via SIGINT internally,
which routes straight to ``shutdown-timeout`` (default 5
seconds); ``graceful-timeout`` does not apply on this path.
In-flight requests on other threads have only that window to
finish before they are force-killed. For applications with
longer request handling times, this can mean interrupted
requests on every deploy.

For a clean drain that doesn't rely on mtime detection, set
``WSGIScriptReloading Off`` on the WSGI mount and signal the
daemon group directly after the symlink swap::

    ln -sfn /srv/myapp/releases/NEW /srv/myapp/current.tmp
    mv -T /srv/myapp/current.tmp /srv/myapp/current
    pkill -USR1 -f 'wsgi:app'

SIGUSR1 sent directly to a daemon process (as ``pkill -USR1``
does here) routes through the ``eviction-timeout`` /
``graceful-timeout`` chain, so each daemon process continues
serving in-flight requests until they complete (up to the
configured timeout) before exiting and being replaced by a
fresh process that picks up the new symlink target. Note that
``apachectl graceful`` does not produce this behaviour: the
Apache parent forwards ``SIGTERM`` to mod_wsgi daemons even on
a graceful restart, which goes straight to ``shutdown-timeout``.
This pattern works because the SIGUSR1 is delivered directly
to the daemon, not via Apache. The ``display-name=%{GROUP}`` option is what makes
``pkill -f`` targetable. Script reloading must be disabled
because the symlink swap changes the WSGI script's resolved
mtime; with the default ``WSGIScriptReloading On``, mod_wsgi's
auto-detection races with SIGUSR1 and triggers a SIGINT shutdown
before the graceful drain can complete.

With multiple daemon processes in the group, restarts roll
across them; during the window, some processes may already be
serving the new code while others are still draining the old.
Whether that mixed-version handling is safe depends on
cross-version compatibility; see the earlier note.

Caveats:

* The directory chain leading to the WSGI script needs ``Options
  +FollowSymLinks`` (or ``+SymLinksIfOwnerMatch`` if the deploy
  user owns the target) to be in effect, since path resolution
  goes through the ``current`` symlink. On a system Apache where
  you control the configuration this is usually fine; on a
  hardened or hosted setup it may need to be granted explicitly.
* This pattern is all-or-nothing per cutover. There is no canary
  and no per-request routing; reach for the parallel-daemon-
  groups patterns below if either is needed.

Version Selection Inside The WSGI Script
-----------------------------------------

For environments where you can't or don't want to declare additional
daemon process groups (shared hosting, a locked-down system Apache,
``.htaccess``-only access), version selection can live inside the
WSGI script itself. The Apache configuration declares one daemon
process group with no ``python-home=``; the WSGI script activates
the right virtualenv and adds the right code directory to
``sys.path`` when it is loaded.

The on-disk layout is two parallel release roots, each with its own
code and virtualenv::

    /srv/myapp/v1/code/
    /srv/myapp/v1/venv/
    /srv/myapp/v2/code/
    /srv/myapp/v2/venv/

The WSGI script for v1 looks like::

    import sys

    python_home = '/srv/myapp/v1/venv'

    activate_this = f'{python_home}/bin/activate_this.py'
    exec(open(activate_this).read(), {'__file__': activate_this})

    sys.path.insert(0, '/srv/myapp/v1/code')

    from myapp import application

The WSGI script for v2 is identical except for the ``v1`` references.
The activation form shown assumes the virtualenv was created with
``uv venv`` or ``virtualenv``, which generate ``activate_this.py``;
for ``python -m venv`` the equivalent uses ``site.addsitedir()``.
:doc:`virtual-environments` covers both forms in detail, including
the empty-``python-home`` trick that prevents packages installed
against the underlying Python from leaking into the application.

The recycle that follows the script change gives the daemon process
a clean Python interpreter that runs the new script's path setup
from scratch, so a virtualenv change is applied cleanly even though
there is only one daemon process group.

Three flavours of cutover are possible. The recommended form is:

**Edit in place (recommended).** Generate a new WSGI file containing
the v2 paths under a temporary name in the same directory, then
rename it atomically over the live WSGI script::

    cp myapp.wsgi.new /srv/myapp/myapp.wsgi.tmp
    mv -f /srv/myapp/myapp.wsgi.tmp /srv/myapp/myapp.wsgi

The rename updates the directory entry; the new file's modification
time is fresh, so mod_wsgi sees a change on its next stat and
recycles the daemon. There is no symlink in play, so this works
regardless of the directory's ``Options FollowSymLinks`` setting.

**Marker file read by the script.** The WSGI script itself is
static and never changes; it reads a marker file at module load
time and resolves paths from there::

    import sys

    with open('/srv/myapp/current.txt') as f:
        version = f.read().strip()

    python_home = f'/srv/myapp/{version}/venv'

    activate_this = f'{python_home}/bin/activate_this.py'
    exec(open(activate_this).read(), {'__file__': activate_this})

    sys.path.insert(0, f'/srv/myapp/{version}/code')

    from myapp import application

Cutover atomically renames the new marker over ``current.txt`` and
then ``touch``\ es the WSGI script to trigger the recycle. Useful
when the per-version path setup is non-trivial and you'd rather not
regenerate the whole script on each deploy.

**WSGI script as a symlink.** The WSGI script file itself is a
symlink that points at one of ``myapp-v1.wsgi`` or
``myapp-v2.wsgi``; cutover retargets the symlink (as with the
atomic code-root swap, the retarget alone is enough to change
which file mod_wsgi resolves to, so no separate ``touch`` is
needed unless the two targets share the same mtime). This works,
but the directory holding the WSGI script needs ``Options
+FollowSymLinks`` (or ``+SymLinksIfOwnerMatch`` if the deploy
user owns the target) to be in effect. On hardened or
hosted Apache configurations that's not always the case, and the
audience for this whole pattern is exactly the audience that may
not have the access to grant it. Use only when the symlink option
is already cleared elsewhere in your deployment tooling.

The edit-in-place and symlink flavours rely on the WSGI script's
modification time changing to trigger the daemon process group to
recycle; the marker-file flavour relies on the explicit ``touch``
of the script noted above for the same reason. As with the
atomic code-root swap, the script-mtime trigger goes via SIGINT
and ``shutdown-timeout`` rather than the graceful drain chain;
in-flight requests on other threads have only ``shutdown-
timeout`` (default 5 seconds) to finish before being
force-killed.

For a clean drain in any of the three flavours, set
``WSGIScriptReloading Off`` on the WSGI mount and signal the
daemon group directly after the file change::

    pkill -USR1 -f 'wsgi:app'

Script reloading must be disabled because the edit-in-place and
symlink flavours change the WSGI script's mtime on cutover; with
reloading enabled, mod_wsgi's auto-detection races with SIGUSR1
and triggers a SIGINT shutdown before the graceful drain can
complete. With reloading off, SIGUSR1 is the sole trigger; the
marker-file flavour can also drop its accompanying ``touch``
since nothing else depends on the script's mtime.

The recycled interpreter loads the new script's path setup from
scratch, so the venv switch still applies. The trade-off is
mixed-version request handling during the graceful window, as
described in the earlier note.

Caveats common to all three flavours:

* Don't combine with ``python-home=`` or ``WSGIPythonPath`` on the
  daemon process group. Those options set up the interpreter
  *before* the script runs and conflict with in-script
  activation. Leave them off and let the script do the work.
* There is no warm previous interpreter to fall back to. The
  recycle is the cutover; rollback means another edit and another
  recycle, not an instant flip.
* Cutover is all-or-nothing per recycle. There is no canary, no
  per-request routing.

Parallel Daemon Process Groups
-------------------------------

The canonical single-instance pattern declares two persistent
daemon process groups. One is the live target at any moment; the
other is the idle target that the next deploy updates and verifies
before traffic is flipped. After the flip, their roles swap: the
previously-live group becomes the idle target for the deploy
after that.

The two groups are typically named ``app:blue`` and ``app:green``,
following the standard blue/green deployment convention. The
names are stable. Don't replace them with ``v1``, ``v2``,
``v3`` per release: changing ``WSGIDaemonProcess`` declarations
requires an Apache restart, which defeats the no-restart cutover
this pattern is meant to enable. Both groups are committed once::

    WSGIDaemonProcess app:blue \
        processes=4 threads=15 \
        user=appsvc group=appsvc \
        python-home=/srv/myapp/blue/venv \
        home=/srv/myapp/blue/code \
        display-name=%{GROUP}

    WSGIDaemonProcess app:green \
        processes=4 threads=15 \
        user=appsvc group=appsvc \
        python-home=/srv/myapp/green/venv \
        home=/srv/myapp/green/code \
        display-name=%{GROUP}

Both daemon groups are visible in ``ps`` output as
``(wsgi:app:blue)`` and ``(wsgi:app:green)`` thanks to
``display-name=%{GROUP}``. Each owns its own virtualenv via
``python-home=``, so dependency changes are isolated to whichever
side is being updated. The per-component virtualenv rationale is
covered in :doc:`security-hardening`.

The on-disk layout matches the daemon group names::

    /srv/myapp/blue/code/
    /srv/myapp/blue/venv/
    /srv/myapp/green/code/
    /srv/myapp/green/venv/

The deploy cycle alternates which side is updated. Suppose
``app:green`` is currently live:

1. Update files in ``/srv/myapp/blue/`` (the idle side). This is
   safe because no traffic is being routed there.
2. Recycle the blue daemon group so its processes pick up the new
   code: ``pkill -USR1 -f 'wsgi:app:blue'``.
3. Validate blue out-of-band, for example via the header-pinned
   canary form of the dispatch script described in the next
   section, or a private health-check route.
4. Flip the routing source of truth (the dispatch script or
   ``RewriteMap``) to point at ``app:blue``. Now blue is live,
   green is idle.
5. The next deploy targets green; the cycle continues.

There is no decommissioning step: both groups stay running across
deploys, and the previously-live side becomes the next deploy
target. Rollback is also covered by this layout, since the
previously-live side is still warm and serving the old code in
its sys.modules; rolling back is just flipping the routing source
back.

The trade-off is resource use: running both groups in parallel
roughly doubles the resident memory and process count compared to
a single-group setup. On small hosts this can be material; on
hosts that can afford it, the rollback story is the strongest of
any pattern in this guide.

What's missing from the snippet above is *how* requests pick a
daemon process group. The two practical mechanisms are
``WSGIDispatchScript`` (per-request Python routing) and
``mod_rewrite``'s ``RewriteMap`` (lookup-table routing), described
in the next two sections. Either can drive the cutover; pick the
one that matches the kind of switch you want to do.

Routing The Switch With WSGIDispatchScript
-------------------------------------------

A dispatch script is a Python file that mod_wsgi runs early in
request handling to override the daemon process group (and
optionally the application group or callable) the request would
otherwise be dispatched to. The full reference is on the
:doc:`../configuration-directives/WSGIDispatchScript` page; the
behaviour relevant to upgrades is:

* The script defines a top-level ``process_group(environ)`` callable
  that returns the name of the daemon process group to dispatch
  to, or ``None`` to leave the configured default in place.
* The callable runs once per request. Its return value is not
  cached, so routing decisions can be different from one request
  to the next.
* The script is loaded in the embedded Apache child interpreter,
  not in the daemon process group it routes to. Editing the script
  and waiting for its modification time to change triggers a
  reload on the next request that needs it, with no Apache
  restart.
* If ``WSGIRestrictProcess`` is configured in the request's scope,
  the dispatched group must be in the allowed list, otherwise the
  request fails. Make sure the candidate groups are reachable from
  the location where the application is mounted.

The directive is added alongside the WSGI mount::

    WSGIDispatchScript /etc/apache2/wsgi/dispatch.py

In the examples below, ``app:blue`` is the side currently being
verified or rolled out and ``app:green`` is the previously-live
side. After a successful cutover the roles swap; the script
logic stays the same shape but the names are flipped on the next
deploy.

A minimal hard-cutover dispatch script that sends all traffic to
blue::

    def process_group(environ):
        return 'app:blue'

A percentage canary that sends 10% of requests to blue::

    import random

    def process_group(environ):
        if random.random() < 0.10:
            return 'app:blue'
        return 'app:green'

A sticky canary that hashes a session-stable identifier so the
same user lands consistently in the same bucket across requests::

    import hashlib

    def process_group(environ):
        cookie = environ.get('HTTP_COOKIE', '')
        marker = 'sessionid='
        if marker in cookie:
            sid = cookie.split(marker, 1)[1].split(';', 1)[0]
            digest = hashlib.sha256(sid.encode()).hexdigest()
            bucket = int(digest, 16) % 100
            if bucket < 10:
                return 'app:blue'
        return 'app:green'

A header-pinned canary for staff or internal traffic, where a
trusted upstream proxy adds an ``X-Canary: 1`` header on requests
from the testing pool::

    def process_group(environ):
        if environ.get('HTTP_X_CANARY') == '1':
            return 'app:blue'
        return 'app:green'

For the header-pinned form, make sure the front end strips
``X-Canary`` from untrusted client traffic so end users can't opt
themselves into the canary; see
:doc:`running-behind-a-reverse-proxy` for the relevant trust
model.

In-flight requests already routed to the previously-live group
are not interrupted when the dispatch script changes; they finish
in that group's daemon processes. Only requests that arrive after
the reload see the new routing.

Routing The Switch With mod_rewrite And A Map File
---------------------------------------------------

When the cutover is "all traffic moves from green to blue at
this moment" and the per-request logic of a dispatch script
feels heavyweight, ``mod_rewrite``'s ``RewriteMap`` directive is
a lighter-weight alternative. A text map file holds a single
entry; ``WSGIProcessGroup`` is set from the map result via an
Apache environment variable; editing the map file flips the
route::

    RewriteEngine On
    RewriteMap wsgilive txt:/etc/apache2/wsgi-live.txt

    RewriteRule . - [E=PROCESS_GROUP:${wsgilive:current|app:maintenance}]
    WSGIProcessGroup %{ENV:PROCESS_GROUP}

The map file ``/etc/apache2/wsgi-live.txt`` contains a single
entry naming the live group::

    current  app:green

To cut over, write a new version of the map file under a
temporary name in the same directory and rename it over the
original::

    printf 'current  app:blue\n' > /etc/apache2/wsgi-live.txt.tmp
    mv -f /etc/apache2/wsgi-live.txt.tmp /etc/apache2/wsgi-live.txt

Apache notices the modification time change on the map file and
rereads it on the next request. No Apache restart is needed.

Notes:

* ``RewriteMap`` is only valid in server config or virtual host
  scope, not in ``<Directory>`` or ``.htaccess``. The
  ``RewriteRule`` setting the environment variable, however,
  can live in the location where the WSGI mount lives.
* The default value (``|app:maintenance`` above) is what you get
  when the map lookup misses. Don't set it to whichever group is
  currently live: that forces an Apache config edit and graceful
  restart on every cutover, defeating the point of using a map
  file. The recommended pattern is to declare a third daemon
  process group dedicated to a maintenance page, alongside blue
  and green::

      WSGIDaemonProcess app:maintenance processes=1 threads=1 \
          user=appsvc group=appsvc \
          python-home=/srv/myapp/maintenance/venv \
          home=/srv/myapp/maintenance/code \
          display-name=%{GROUP}

  The maintenance code directory holds a minimal WSGI app that
  returns a 503 with a "service unavailable" message::

      def application(environ, start_response):
          body = b'Service temporarily unavailable.\n'
          start_response('503 Service Unavailable', [
              ('Content-Type', 'text/plain'),
              ('Content-Length', str(len(body))),
              ('Retry-After', '60'),
          ])
          return [body]

  If the map file is ever missing, mistyped, or briefly truncated
  mid-rename, requests land on the maintenance page rather than
  reaching a potentially-wrong-version daemon, and the fallback
  default never has to change.

  The same maintenance group is also useful when routing is
  driven by ``WSGIDispatchScript`` (above). Most dispatch-driven
  deploys flip traffic instantly between blue and green, but
  some upgrades need a brief outage, for example a data
  migration that needs exclusive database access. Having
  ``process_group(environ)`` return ``'app:maintenance'`` for
  the duration parks every request on the maintenance page;
  reverting the dispatch script restores normal routing.
* For high-volume sites where text-map lookup overhead matters,
  ``mod_rewrite`` also supports ``dbm:`` maps. These need to be
  rebuilt with ``httxt2dbm`` after each edit and add complexity
  that usually isn't worth it for a single-key cutover map.

This pattern handles full cutovers cleanly. It does not naturally
support canary or sticky routing; reach for ``WSGIDispatchScript``
for those.

Rollback Recipes
----------------

Each switching mechanism has a symmetric rollback. All assume that
the previous version's daemon process group is still running:

* **Dispatch script.** Revert the script's contents (or just edit
  it to return the previously-live group name again) and rename
  the new file into place. Apache reloads the script on the next
  request that needs it. The previously-live group is still warm
  and serving the old code, so the flip is instant.
* **mod_rewrite map file.** Atomically rewrite the map back to
  the previously-live group::

      printf 'current  app:green\n' > /etc/apache2/wsgi-live.txt.tmp
      mv -f /etc/apache2/wsgi-live.txt.tmp /etc/apache2/wsgi-live.txt

* **Version selection inside the WSGI script.** Either rename the
  previous WSGI script back into place, or rewrite the marker file
  and ``touch`` the script to recycle the daemon. There is no
  warm previous interpreter, so rollback in this pattern still
  costs a recycle.
* **Atomic code-root swap.** Retarget ``current`` to the previous
  release directory. The previous release is still on disk, so
  this is a single symlink flip; mod_wsgi detects the path change
  on the next stat of the WSGI script and recycles. No redeploy
  is needed::

      ln -sfn /srv/myapp/releases/PREVIOUS /srv/myapp/current.tmp
      mv -T /srv/myapp/current.tmp /srv/myapp/current

In each case, requests already routed to the new version finish in
the new version. Only requests arriving after the rollback are
served by the previous version.

Database Schema Considerations
------------------------------

Whenever both versions of the application are running at the same
time (the parallel daemon process group patterns above), the
database schema must be compatible with both versions for the
duration of the overlap. The standard pattern for this is:

1. Apply backwards-compatible (additive) schema changes first,
   while only the old version is running. The old version
   ignores the new columns; the new version will use them.
2. Roll out the new version alongside the old. Cut over traffic.
3. Once the old version will no longer be reached for rollback
   (typically a later deploy cycle when the old side is itself
   overwritten), apply any cleanup migrations that drop or
   rename columns the new version no longer needs.

This is a general blue/green deployment topic rather than a
mod_wsgi-specific one, but it's worth flagging here because the
overlap window is what makes the rollback story strong: if the
schema only supports the new version, rollback to the old stops
being safe.

See Also
--------

* :doc:`daemon-mode` for the conceptual model behind the parallel
  daemon process groups used in the blue/green pattern.
* :doc:`request-pipeline` for the SIGUSR1 / ``eviction-timeout``
  / ``graceful-timeout`` drain semantics that govern the cutover.
* :doc:`reloading-source-code` for the full mechanics of
  script-file recycling and signal-driven daemon restart, plus an
  automatic source-change monitor.
* :doc:`virtual-environments` for the full reference on activating
  per-application virtualenvs from inside a WSGI script.
* :doc:`security-hardening` for the per-component virtualenv
  rationale and ``WSGIRestrictProcess`` boundary checking.
* :doc:`../configuration-directives/WSGIDispatchScript` for the
  full directive reference.
* :doc:`../configuration-directives/WSGIProcessGroup` and
  :doc:`../configuration-directives/WSGIRestrictProcess` for
  process-group selection and restriction semantics.
