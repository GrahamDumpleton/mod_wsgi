===============
Error Reference
===============

mod_wsgi tags certain log messages with a stable error code of the form
``WSGI####``. The code prefixes the logged message text in the Apache
error log so an operator can identify the error precisely and look up its
meaning here, regardless of how the surrounding message text might evolve
in future releases.

Example log line, with the error code highlighted::

    [Mon Jan 01 12:00:00.000000 2026] [wsgi:crit] [pid 12345] WSGI0001: Python initialisation failed; Python based handlers will not be available in this child process.

Only mod_wsgi's higher-severity log messages currently carry an error
code. The reference is being expanded incrementally; codes are allocated
sequentially and never reassigned, so a code that is not listed here
either belongs to a future release or has been retired.

Severity tiers
==============

mod_wsgi follows the standard Apache severity ladder. The interpretation
used in this reference:

EMERG
    Apache itself or the wider system is unusable.

ALERT
    A whole process or service is unusable. Operator action required
    immediately. Typically: this daemon process cannot continue.

CRIT
    A major service-impacting failure, but the server is still functional
    in some capacity (for example, a single daemon group is degraded but
    other groups continue serving requests).

ERR
    An error scoped to a single request, single thread, or a degraded
    but still-running subsystem. The daemon process or Apache child
    continues to run; the operation that fired the error did not
    complete successfully.

WARNING
    A noteworthy condition that does not in itself prevent operation:
    a configured limit could not be applied, an optional feature is
    unavailable, a transient situation will be retried, or a
    diagnostic check predicts a later failure.

Each entry below records the severity at which the message is emitted,
along with the cause, the immediate outcome (what mod_wsgi does next),
and any operator action that is appropriate.

Error codes
===========

.. _WSGI0001:

WSGI0001 — Python initialisation failed in Apache child process
---------------------------------------------------------------

:Severity: CRIT
:Source: ``src/server/mod_wsgi.c``

:Logged message:
   ``Python initialisation failed in Apache child process; Python based
   handlers will not be available.``

:Cause:
   ``wsgi_python_init()`` failed when the Apache child process was
   initialising the embedded Python interpreter. This is almost always a
   Python configuration problem (an invalid ``WSGIPythonHome``, missing
   or unreadable Python installation, an incompatible Python build) or
   a system-level resource exhaustion (memory).

:Outcome:
   The Apache child process logs the error and continues running, but
   ``wsgi_python_initialized`` remains 0. All Python-bound handlers will
   short-circuit and any embedded-mode WSGI request will return a
   500-class error. Daemon-mode requests are unaffected unless the daemon
   processes are also failing to initialise (see :ref:`WSGI0028`).

:Operator action:
   Check the Apache error log for any prior Python errors emitted during
   startup. Verify that ``WSGIPythonHome`` (if set) points at a usable
   Python installation, that the Python version is supported by this
   build of mod_wsgi, and that the host has free memory. If the failure
   reproduces, raise the Apache ``LogLevel`` for the ``wsgi`` module to
   ``debug`` to obtain a more detailed Python traceback.

.. _WSGI0002:

WSGI0002 — Python child initialisation failed in Apache child process
---------------------------------------------------------------------

:Severity: CRIT
:Source: ``src/server/mod_wsgi.c``

:Logged message:
   ``Python child initialisation failed in Apache child process; Python
   based handlers will not be available.``

:Cause:
   ``wsgi_python_child_init()`` failed *after* ``wsgi_python_init()``
   succeeded. The base interpreter was created but per-child setup
   (Python type registration, the interpreters dictionary, etc.) could
   not complete. Typical underlying causes are memory exhaustion or a
   corrupted Python state that surfaced only during type registration.

:Outcome:
   The Apache child process logs the error and continues running, but
   embedded-mode Python handlers will not work in this child for the
   rest of its lifetime. ``wsgi_python_initialized`` is left 0 so all
   Python-bound code paths short-circuit cleanly.

:Operator action:
   Same as :ref:`WSGI0001`. If both messages fire from the same child,
   the underlying problem is the Python interpreter rather than mod_wsgi
   per se — verify the Python installation independently.

.. _WSGI0003:

WSGI0003 — Unable to change root directory for daemon process
-------------------------------------------------------------

:Severity: ALERT
:Source: ``src/server/wsgi_daemon.c``

:Logged message:
   ``Unable to change root directory to '<root>'. Daemon process will
   exit.``

:Cause:
   ``chroot()`` failed during daemon-process startup when the
   ``WSGIDaemonProcess`` directive specified a ``root=`` chroot target.
   Typical underlying causes are: the daemon process is not running with
   sufficient privilege to call ``chroot``, the chroot directory does
   not exist, or the path is not a directory.

:Outcome:
   The daemon process exits after a 20-second anti-fork-bomb delay
   (the failure is logged a second time via the :ref:`WSGI0025`
   companion message). Apache respawns it; the same failure will recur
   until the underlying cause is fixed.

:Operator action:
   Verify that the chroot directory exists and that the Apache parent
   process (which performs the fork before the daemon drops privileges)
   has CAP_SYS_CHROOT or the equivalent. Most Linux deployments require
   running Apache as root for ``chroot=`` to work.

.. _WSGI0004:

WSGI0004 — Unable to set group id for daemon process
----------------------------------------------------

:Severity: ALERT
:Source: ``src/server/wsgi_daemon.c``

:Logged message:
   ``Unable to set group id to gid=<gid>. Daemon process will exit.``

:Cause:
   ``setgid()`` failed during daemon-process startup when applying the
   group specified by ``WSGIDaemonProcess group=...``. The most common
   cause is that the daemon process is not running with sufficient
   privilege to change group; this should not happen on a normal Apache
   install where the parent runs as root.

:Outcome:
   The daemon process exits after a 20-second anti-fork-bomb delay
   (the failure is logged a second time via the :ref:`WSGI0025`
   companion message). Apache respawns it.

:Operator action:
   Verify the group exists and that Apache is running with sufficient
   privilege to change group identity at fork time.

.. _WSGI0005:

WSGI0005 — Unable to set supplementary groups for daemon process
----------------------------------------------------------------

:Severity: ALERT
:Source: ``src/server/wsgi_daemon.c``

:Logged message:
   ``Unable to set supplementary groups for uname=<user> of '<groups>'.
   Daemon process will exit.``

:Cause:
   ``setgroups()`` failed when applying the supplementary group list
   given via ``WSGIDaemonProcess supplementary-groups=...``. Either one
   of the named groups does not exist, the list contains an invalid
   identifier, or the process lacks privilege to set supplementary
   groups.

:Outcome:
   The daemon process exits after a 20-second anti-fork-bomb delay
   (the failure is logged a second time via the :ref:`WSGI0025`
   companion message). Apache respawns it.

:Operator action:
   Confirm every group named in the directive exists. Verify Apache has
   privilege to manage supplementary groups at fork time.

.. _WSGI0006:

WSGI0006 — Unable to initialise default groups for daemon process
-----------------------------------------------------------------

:Severity: ALERT
:Source: ``src/server/wsgi_daemon.c``

:Logged message:
   ``Unable to initialise groups for uname=<user> and gid=<gid>.
   Daemon process will exit.``

:Cause:
   ``initgroups()`` failed while loading the supplementary-group list
   for the daemon's user from the system group database. Most often the
   user does not exist in the system database at the time the daemon
   process starts (NSS/LDAP unavailable, user removed, etc.).

:Outcome:
   The daemon process exits after a 20-second anti-fork-bomb delay
   (the failure is logged a second time via the :ref:`WSGI0025`
   companion message). Apache respawns it.

:Operator action:
   Verify the user named on ``WSGIDaemonProcess user=...`` resolves
   correctly in the system group database (``id <user>``).

.. _WSGI0007:

WSGI0007 — Unable to change to user id for daemon process
---------------------------------------------------------

:Severity: ALERT
:Source: ``src/server/wsgi_daemon.c``

:Logged message:
   ``Unable to change to uid=<uid>. Daemon process will exit.``

:Cause:
   ``setuid()`` failed during daemon-process startup. On Linux this is
   most often caused by the target user reaching their per-user process
   limit (``RLIMIT_NPROC``); ``setuid()`` returns ``EAGAIN`` in that
   case. Other causes are insufficient privilege to change identity at
   all.

:Outcome:
   The daemon process exits after a 20-second anti-fork-bomb delay
   (the failure is logged a second time via the :ref:`WSGI0008`
   companion message). Apache respawns it; the same failure will
   recur until the cause is fixed.

:Operator action:
   Check ``ulimit -u`` for the target user. If at or near the limit,
   raise the per-user process limit or reduce the number of processes
   the user is running.

.. _WSGI0008:

WSGI0008 — Daemon process left in unspecified state after setuid failure
------------------------------------------------------------------------

:Severity: ALERT
:Source: ``src/server/wsgi_daemon.c``

:Logged message:
   ``Daemon process configuration failed; process left in unspecified
   state. Daemon process will exit and be restarted after a delay.``

:Cause:
   Companion log message to :ref:`WSGI0007`. Emitted immediately after
   a ``setuid`` failure to make explicit that the daemon was unable to
   drop privileges and is therefore exiting rather than continuing in a
   potentially elevated state.

:Outcome:
   The daemon process exits after a 20-second anti-fork-bomb delay.
   Apache respawns it.

:Operator action:
   See :ref:`WSGI0007`.

.. _WSGI0009:

WSGI0009 — Unable to change working directory for daemon process
----------------------------------------------------------------

:Severity: ALERT
:Source: ``src/server/wsgi_daemon.c``

:Logged message:
   ``Unable to change working directory to '<path>'. Daemon process
   will exit.``

:Cause:
   ``chdir()`` failed when applying the directory specified by
   ``WSGIDaemonProcess home=...``. Most often the directory does not
   exist, is not a directory, or is unreadable to the daemon user.

:Outcome:
   The daemon process exits after a 20-second anti-fork-bomb delay
   (the failure is logged a second time via the :ref:`WSGI0025`
   companion message). Apache respawns it.

:Operator action:
   Verify the path exists, is a directory, and is accessible to the
   daemon user.

.. _WSGI0010:

WSGI0010 — Unable to change working directory to user home directory
--------------------------------------------------------------------

:Severity: ALERT
:Source: ``src/server/wsgi_daemon.c``

:Logged message:
   ``Unable to change working directory to home directory '<path>' for
   uid=<uid>. Daemon process will exit.``

:Cause:
   No explicit ``home=`` was given on ``WSGIDaemonProcess`` and the
   daemon attempted to fall back to the home directory of the user it
   is running as. ``chdir()`` to that home directory failed — usually
   because the home directory does not exist or is unreadable.

:Outcome:
   The daemon process exits after a 20-second anti-fork-bomb delay
   (the failure is logged a second time via the :ref:`WSGI0025`
   companion message). Apache respawns it.

:Operator action:
   Either give an explicit ``home=`` value on ``WSGIDaemonProcess``, or
   ensure the user's home directory exists and is accessible.

.. _WSGI0011:

WSGI0011 — Unable to determine home directory for daemon process user
---------------------------------------------------------------------

:Severity: ALERT
:Source: ``src/server/wsgi_daemon.c``

:Logged message:
   ``Unable to determine home directory for uid=<uid>. Daemon process
   will exit.``

:Cause:
   No explicit ``home=`` was given on ``WSGIDaemonProcess`` and the
   ``getpwuid()`` lookup for the daemon user's home directory failed.
   Usually the user is not present in the system password database at
   the time the daemon starts (NSS/LDAP unavailable, user removed).

:Outcome:
   The daemon process exits after a 20-second anti-fork-bomb delay
   (the failure is logged a second time via the :ref:`WSGI0025`
   companion message). Apache respawns it.

:Operator action:
   Verify the user resolves correctly (``getent passwd <uid>``), or set
   an explicit ``home=`` on ``WSGIDaemonProcess`` so no lookup is
   required.

.. _WSGI0012:

WSGI0012 — Unable to create UNIX domain socket for daemon process
-----------------------------------------------------------------

:Severity: ALERT
:Source: ``src/server/wsgi_daemon.c``

:Logged message:
   ``Unable to create unix domain socket for daemon process '<group>'.
   Daemon group will not start.``

:Cause:
   The ``socket(AF_UNIX, SOCK_STREAM, 0)`` call failed during daemon
   listener setup. Almost always a process or system file-descriptor
   exhaustion.

:Outcome:
   Daemon listener setup is aborted. The Apache parent fails to start
   the affected daemon group.

:Operator action:
   Check the file-descriptor limits (``ulimit -n``) for the Apache
   user, and the system-wide limit (``/proc/sys/fs/file-max`` on
   Linux). Reduce open files in other processes if exhausted.

.. _WSGI0013:

WSGI0013 — Unable to bind UNIX domain socket for daemon process
---------------------------------------------------------------

:Severity: ALERT
:Source: ``src/server/wsgi_daemon.c``

:Logged message:
   ``Unable to bind unix domain socket '<path>'. Daemon group will not
   start.``

:Cause:
   ``bind()`` on the daemon's listener socket failed. Common causes:
   the parent directory of the socket does not exist or is not
   writable; the socket path is too long for ``sun_path`` (see also
   the WARNING that fires earlier when path length is suspect); the
   socket file already exists and could not be removed.

:Outcome:
   Daemon listener setup is aborted. The Apache parent fails to start
   the affected daemon group.

:Operator action:
   Verify the socket directory exists, is writable by the user that
   creates the socket, and that no stale file blocks the path.
   Configure ``WSGISocketPrefix`` to a shorter path if length is the
   issue.

.. _WSGI0014:

WSGI0014 — Unable to listen on UNIX domain socket for daemon process
--------------------------------------------------------------------

:Severity: ALERT
:Source: ``src/server/wsgi_daemon.c``

:Logged message:
   ``Unable to listen on unix domain socket '<path>'. Daemon group will
   not start.``

:Cause:
   ``listen()`` on the daemon's listener socket failed after a
   successful ``bind()``. This is rare; the most common cause is a
   resource limit or kernel-level socket exhaustion.

:Outcome:
   Daemon listener setup is aborted. The Apache parent fails to start
   the affected daemon group.

:Operator action:
   Inspect kernel logs (``dmesg``, ``journalctl``) for socket-related
   messages near the time of failure. Check system limits.

.. _WSGI0015:

WSGI0015 — Unable to change owner of UNIX domain socket for daemon process
--------------------------------------------------------------------------

:Severity: ALERT
:Source: ``src/server/wsgi_daemon.c``

:Logged message:
   ``Unable to change owner of unix domain socket '<path>' to uid=<uid>.
   Daemon group will not start.``

:Cause:
   ``chown()`` on the daemon listener socket failed. The Apache parent
   needs to set the socket's owner so the Apache child processes (and
   only those) can connect to it. Usually a privilege or filesystem
   problem.

:Outcome:
   Daemon listener setup is aborted. The Apache parent fails to start
   the affected daemon group.

:Operator action:
   Ensure the Apache parent runs with sufficient privilege to chown
   the socket. Verify the filesystem hosting the socket allows owner
   changes.

.. _WSGI0016:

WSGI0016 — Wait on worker thread wakeup condition variable failed
-----------------------------------------------------------------

:Severity: CRIT
:Source: ``src/server/wsgi_daemon.c``

:Logged message:
   ``Wait on thread <id> wakeup condition variable failed; worker thread
   will exit.``

:Cause:
   ``apr_thread_cond_wait()`` returned an error in the worker
   acquisition path. APR cond-wait failure is a system-level anomaly
   that normally indicates the underlying pthreads primitive is in a
   broken state.

:Outcome:
   The worker's wait returns the error; the worker thread falls
   through to its caller, which typically exits the worker. The
   daemon process continues running but with reduced thread capacity
   until restart.

:Operator action:
   Restart the daemon process. If this recurs, escalate as a likely
   APR/pthreads bug — capture the daemon log and any kernel messages.

.. _WSGI0017:

WSGI0017 — Unable to acquire accept mutex; daemon shutting down
---------------------------------------------------------------

:Severity: CRIT
:Source: ``src/server/wsgi_daemon.c``

:Logged message:
   ``Unable to acquire accept mutex '<path>'. Daemon process will shut
   down.``

:Cause:
   ``apr_proc_mutex_lock()`` on the cross-process accept mutex failed
   in a daemon process. This typically means the mutex was destroyed
   by an external event (e.g. Apache parent exited, or sysvsem
   semaphore set was removed by ``ipcrm``).

:Outcome:
   The daemon flags itself for shutdown, sends ``SIGTERM`` to its own
   pid, and exits. Apache respawns it.

:Operator action:
   Usually no action required — this fires during Apache restart or
   shutdown by design. If it fires unprompted, investigate whether
   the system's IPC tables are being cleared by other processes.

.. _WSGI0018:

WSGI0018 — Unable to poll daemon socket; daemon shutting down
-------------------------------------------------------------

:Severity: CRIT
:Source: ``src/server/wsgi_daemon.c``

:Logged message:
   ``Unable to poll daemon socket for '<path>'. Daemon process will shut
   down.``

:Cause:
   ``apr_pollset_poll()`` on the daemon's listener socket returned a
   non-EINTR error. Usually a kernel-level problem with the
   underlying file descriptor.

:Outcome:
   The daemon flags itself for shutdown, sends ``SIGTERM`` to its own
   pid, and exits. Apache respawns it.

:Operator action:
   Inspect kernel logs near the time of failure. If recurrent,
   investigate filesystem or kernel issues with UNIX domain sockets.

.. _WSGI0019:

WSGI0019 — Unable to release accept mutex
-----------------------------------------

:Severity: CRIT
:Source: ``src/server/wsgi_daemon.c``

:Logged message:
   ``Unable to release accept mutex '<path>'; worker thread will exit.``

:Cause:
   ``apr_proc_mutex_unlock()`` on the cross-process accept mutex
   failed after a successful ``accept()``. This is unusual and
   suggests the mutex is in an inconsistent state.

:Outcome:
   The worker thread releases its slot in the worker pool and exits.
   The daemon process continues but the accept mutex may be left
   held, blocking other daemon processes in the same group from
   accepting connections.

:Operator action:
   Restart the affected daemon group. If recurrent, escalate as a
   likely APR or kernel-level issue with the chosen lock mechanism.

.. _WSGI0020:

WSGI0020 — Unable to create worker thread condition variable
------------------------------------------------------------

:Severity: ALERT
:Source: ``src/server/wsgi_daemon.c``

:Logged message:
   ``Unable to create worker thread <i> condition variable in daemon
   process '<group>'. Daemon process will exit and be restarted after
   a delay.``

:Cause:
   ``apr_thread_cond_create()`` failed when initialising a worker
   thread's wakeup condition variable during daemon startup. Almost
   always a memory or thread-resource exhaustion.

:Outcome:
   The daemon process exits after a 20-second anti-fork-bomb delay.
   Apache respawns it.

:Operator action:
   Check memory and thread limits on the host. Reduce the
   ``threads=`` value on ``WSGIDaemonProcess`` if the daemon is
   configured for an unusually high number of workers.

.. _WSGI0021:

WSGI0021 — Unable to create worker thread mutex
-----------------------------------------------

:Severity: ALERT
:Source: ``src/server/wsgi_daemon.c``

:Logged message:
   ``Unable to create worker thread <i> mutex in daemon process
   '<group>'. Daemon process will exit and be restarted after a
   delay.``

:Cause:
   ``apr_thread_mutex_create()`` failed when initialising a worker
   thread's state mutex during daemon startup. Almost always a
   memory or thread-resource exhaustion.

:Outcome:
   The daemon process exits after a 20-second anti-fork-bomb delay.
   Apache respawns it.

:Operator action:
   See :ref:`WSGI0020`.

.. _WSGI0022:

WSGI0022 — Unable to create worker thread
-----------------------------------------

:Severity: ALERT
:Source: ``src/server/wsgi_daemon.c``

:Logged message:
   ``Unable to create worker thread <i> in daemon process '<group>'.
   Daemon process will exit and be restarted after a delay.``

:Cause:
   ``apr_thread_create()`` failed when starting a worker thread
   during daemon startup. Usually thread-resource exhaustion at the
   process or system level.

:Outcome:
   The daemon process exits after a 20-second anti-fork-bomb delay.
   Apache respawns it.

:Operator action:
   Check thread limits (``ulimit -u``, ``/proc/sys/kernel/threads-max``)
   and reduce ``threads=`` on the daemon group if appropriate.

.. _WSGI0023:

WSGI0023 — Read failed on signal pipe in daemon process
-------------------------------------------------------

:Severity: ALERT
:Source: ``src/server/wsgi_daemon.c``

:Logged message:
   ``Read failed on signal pipe in daemon process '<group>'; daemon
   process will shut down.``

:Cause:
   The daemon process's main loop failed to read from its internal
   signal pipe used to receive shutdown notifications. This indicates
   the pipe is in an unexpected state and the daemon can no longer
   reliably observe shutdown signals.

:Outcome:
   The daemon abandons the main wait loop and proceeds into its
   shutdown path.

:Operator action:
   None required if this fires once during a normal restart. If it
   fires unprompted, investigate file-descriptor leaks or other
   pipe-related problems.

.. _WSGI0024:

WSGI0024 — Unable to spawn daemon process
-----------------------------------------

:Severity: ALERT
:Source: ``src/server/wsgi_daemon.c``

:Logged message:
   ``Unable to spawn daemon process '<group>'. Daemon group will not
   start.``

:Cause:
   ``apr_proc_fork()`` failed in the Apache parent when spawning a
   daemon process for a ``WSGIDaemonProcess`` group. Almost always a
   process-table or memory exhaustion at fork time.

:Outcome:
   Apache aborts the daemon-group setup; the affected group does not
   start.

:Operator action:
   Check process limits and free memory. Reduce ``processes=`` on
   the daemon group, or reduce overall workload, if at the system
   process limit.

.. _WSGI0025:

WSGI0025 — Daemon process left in unspecified state after setup failure
-----------------------------------------------------------------------

:Severity: ALERT
:Source: ``src/server/wsgi_daemon.c``

:Logged message:
   ``Daemon process configuration failed; process left in unspecified
   state. Daemon process will exit and be restarted after a delay.``

:Cause:
   ``wsgi_setup_access()`` returned an error during daemon startup.
   The actual cause will have been logged immediately above as one of
   :ref:`WSGI0003` through :ref:`WSGI0011`. This message is the
   companion log explaining that the daemon is exiting because it
   could not safely complete privilege-drop / chroot / chdir setup.

:Outcome:
   The daemon process exits after a 20-second anti-fork-bomb delay.
   Apache respawns it.

:Operator action:
   See whichever of :ref:`WSGI0003` to :ref:`WSGI0011` was logged
   immediately before this entry.

.. _WSGI0026:

WSGI0026 — Unable to initialise accept mutex in daemon process
--------------------------------------------------------------

:Severity: CRIT
:Source: ``src/server/wsgi_daemon.c``

:Logged message:
   ``Unable to initialise accept mutex '<path>' in daemon process.
   Daemon process will exit and be restarted after a delay.``

:Cause:
   ``apr_proc_mutex_child_init()`` failed when re-attaching the
   shared accept mutex in a freshly forked daemon process. Most
   often the mutex file or sysvsem segment is missing or
   inaccessible to the daemon user after privilege drop.

:Outcome:
   The daemon process exits after a 20-second anti-fork-bomb delay.
   Apache respawns it.

:Operator action:
   Verify ``WSGISocketPrefix`` points at a directory that is
   accessible to the daemon user. If using sysvsem locks, check
   that ``ipcs -s`` shows the expected semaphores and that they
   were not removed externally.

.. _WSGI0027:

WSGI0027 — Unable to initialise signal pipe in daemon process
-------------------------------------------------------------

:Severity: ALERT
:Source: ``src/server/wsgi_daemon.c``

:Logged message:
   ``Unable to initialise signal pipe in daemon process '<group>'.
   Daemon process will exit and be restarted after a delay.``

:Cause:
   ``apr_file_pipe_create()`` failed when the daemon was setting up
   its internal signal pipe used to receive shutdown notifications.
   Almost always a file-descriptor or memory exhaustion.

:Outcome:
   The daemon process exits after a 20-second anti-fork-bomb delay.
   Apache respawns it.

:Operator action:
   Check ``ulimit -n`` for the Apache user, system-wide file
   descriptor limits, and free memory on the host.

.. _WSGI0028:

WSGI0028 — Python initialisation failed in daemon process
---------------------------------------------------------

:Severity: CRIT
:Source: ``src/server/wsgi_daemon.c``

:Logged message:
   ``Python initialisation failed in daemon process '<group>'; Python
   based handlers will not be available.``

:Cause:
   Same as :ref:`WSGI0001` but in a daemon-mode process rather than
   the Apache child. ``wsgi_python_init()`` failed inside the daemon.

:Outcome:
   The daemon process logs the error and continues running, but
   ``wsgi_python_initialized`` remains 0 and any WSGI request routed
   to this daemon group will return a 500-class error.

:Operator action:
   See :ref:`WSGI0001`. If a daemon group has its own
   ``python-home=`` setting, verify it as well.

.. _WSGI0029:

WSGI0029 — Python child initialisation failed in daemon process
---------------------------------------------------------------

:Severity: CRIT
:Source: ``src/server/wsgi_daemon.c``

:Logged message:
   ``Python child initialisation failed in daemon process '<group>';
   Python based handlers will not be available.``

:Cause:
   Same as :ref:`WSGI0002` but in a daemon-mode process.
   ``wsgi_python_child_init()`` failed inside the daemon.

:Outcome:
   The daemon process continues running but cannot serve Python
   requests for the rest of its lifetime.

:Operator action:
   See :ref:`WSGI0002`.

.. _WSGI0030:

WSGI0030 — Unable to create accept lock for daemon group
--------------------------------------------------------

:Severity: CRIT
:Source: ``src/server/wsgi_daemon.c``

:Logged message:
   ``Unable to create accept lock '<path>'. Daemon group will not
   start.``

:Cause:
   ``apr_proc_mutex_create()`` failed when creating the cross-process
   accept mutex used by daemon groups with more than one process.
   Common causes: the lock file directory does not exist or is not
   writable; sysvsem semaphores are exhausted; the chosen lock
   mechanism is not supported on this system.

:Outcome:
   Apache aborts the daemon-group setup; the affected group does not
   start.

:Operator action:
   Verify ``WSGISocketPrefix`` and the lock-file directory. If using
   sysvsem, check ``ipcs -ls`` for limits and ``ipcs -s`` for
   existing semaphore sets.

.. _WSGI0031:

WSGI0031 — Unable to set permissions on sysvsem accept mutex
------------------------------------------------------------

:Severity: CRIT
:Source: ``src/server/wsgi_daemon.c``

:Logged message:
   ``Unable to set permissions on sysvsem accept mutex '<path>'.
   Daemon group will not start.``

:Cause:
   ``semctl(IPC_SET)`` failed when applying owner and mode to the
   sysvsem semaphore set used as the cross-process accept mutex.
   This is required so the daemon user can lock the mutex after
   privilege drop.

:Outcome:
   Apache aborts the daemon-group setup; the affected group does not
   start.

:Operator action:
   Check whether the system's IPC permission policy is being enforced
   by SELinux/AppArmor or another LSM, and that the Apache parent has
   privilege to ``IPC_SET`` on the semaphore set.

.. _WSGI0032:

WSGI0032 — Unable to set permissions on flock accept mutex
----------------------------------------------------------

:Severity: CRIT
:Source: ``src/server/wsgi_daemon.c``

:Logged message:
   ``Unable to set permissions on flock accept mutex '<path>'. Daemon
   group will not start.``

:Cause:
   ``chown()`` on the flock-style accept mutex file failed. Usually a
   filesystem or privilege issue at the lock-file location.

:Outcome:
   Apache aborts the daemon-group setup; the affected group does not
   start.

:Operator action:
   Verify the lock file's parent directory (``WSGISocketPrefix``) is
   on a filesystem that supports ``chown`` and that the Apache parent
   has the required privilege.

.. _WSGI0033:

WSGI0033 — Request origin could not be validated (no magic token)
-----------------------------------------------------------------

:Severity: ALERT
:Source: ``src/server/wsgi_daemon.c``

:Logged message:
   ``Request origin could not be validated; missing magic token.``

:Cause:
   A request arrived at a daemon process via the listener socket but
   did not carry the ``mod_wsgi.magic`` token that the Apache child
   sets on every legitimate proxied request. This indicates either a
   misconfiguration that allows non-mod_wsgi clients to connect to
   the daemon socket, or an attempt to bypass mod_wsgi's request
   origin check.

:Outcome:
   The request is rejected with HTTP 500 and the daemon process pool
   for the request is destroyed.

:Operator action:
   Treat as a security event. Verify that ``WSGISocketPrefix`` points
   at a directory only the Apache user can write to, and that no
   other process is connecting to mod_wsgi daemon sockets directly.

.. _WSGI0034:

WSGI0034 — Request origin could not be validated (magic token mismatch)
-----------------------------------------------------------------------

:Severity: ALERT
:Source: ``src/server/wsgi_daemon.c``

:Logged message:
   ``Request origin could not be validated; magic token mismatch.``

:Cause:
   The request carried a ``mod_wsgi.magic`` token but it did not
   match the value the daemon expects for its own daemon group. This
   can happen if a request meant for one daemon group is somehow
   delivered to a different group's socket, or if a third party is
   forging mod_wsgi proxy requests.

:Outcome:
   The request is rejected with HTTP 500 and the daemon process pool
   for the request is destroyed.

:Operator action:
   Treat as a security event. Same investigation as :ref:`WSGI0033`.

.. _WSGI0035:

WSGI0035 — Unable to setup Python interpreter
---------------------------------------------

:Severity: CRIT
:Source: ``src/server/wsgi_interp.c``

:Logged message:
   ``Unable to setup <interpreter-context> in <process-context>.``
   Interpreter context is ``main interpreter`` or ``sub-interpreter
   '<name>'``; process context is ``embedded mode`` or ``daemon
   process '<group>'``.

:Cause:
   ``newInterpreterObject()`` failed at any step of interpreter
   construction — handle allocation, ``Py_NewInterpreter()``,
   replacement of ``sys.std*`` streams, registering the ``mod_wsgi``
   / ``apache`` extension modules, applying ``WSGIPythonPath``
   entries, etc. Almost always a memory exhaustion, but a corrupted
   Python state or a buggy user-supplied ``mod_wsgi.py`` /
   ``apache.py`` shadowing the extension modules can also surface
   here. Any partially constructed sub-interpreter is cleaned up
   before this message is logged.

:Outcome:
   The caller receives ``NULL`` and treats the interpreter as
   unavailable. The actual Python exception detail is logged
   immediately after this header via the interpreter-init phase
   message (see :ref:`WSGI0188` / :ref:`WSGI0189`).

:Operator action:
   Read the traceback that follows this header to identify the
   underlying cause. Check free memory if a ``MemoryError``. If
   recurrent under load, reduce ``threads=`` / ``processes=`` on
   heavily configured daemon groups.

.. _WSGI0036:

WSGI0036 — Python interpreter configuration failed
--------------------------------------------------

:Severity: CRIT
:Source: ``src/server/wsgi_interp.c``

:Logged message:
   ``Python interpreter configuration failed in <process-context>:
   <message>`` The process context is either ``embedded mode`` or
   ``daemon process '<group>'``.

:Cause:
   A ``PyConfig_*`` API call returned an error during ``wsgi_python_init()``.
   The trailing ``<message>`` carries Python's own description of the
   failure. Most often this is a memory allocation failure, an invalid
   ``WSGIPythonHome`` value, or a Python build/version mismatch.

:Outcome:
   ``wsgi_python_init()`` returns failure; the Apache child or daemon
   process logs the upstream :ref:`WSGI0001`, :ref:`WSGI0028`, or a
   similar message and continues running with Python disabled.

:Operator action:
   Read the trailing Python message in the log entry; it identifies
   the failed config step. Verify ``WSGIPythonHome`` and that the
   Python build is compatible with this mod_wsgi build.

.. _WSGI0037:

WSGI0037 — Unable to initialise Python types for child process
--------------------------------------------------------------

:Severity: CRIT
:Source: ``src/server/wsgi_interp.c``

:Logged message:
   ``Unable to initialise Python types in <process-context>; Python
   based handlers will not be available.`` Process context shape
   as for :ref:`WSGI0036`.

:Cause:
   One of mod_wsgi's internal Python type objects failed
   ``PyType_Ready()`` during ``wsgi_python_child_init()``. This
   normally indicates that the running Python version's C-API has
   changed in a way mod_wsgi does not handle, or that Python state
   is corrupted at the time of initialisation.

:Outcome:
   ``wsgi_python_initialized`` is set to 0 and the function returns
   ``APR_EGENERAL``. The child or daemon process cannot serve Python
   requests for the rest of its lifetime.

:Operator action:
   Verify the running Python version is supported by this build of
   mod_wsgi. Rebuild mod_wsgi against the target Python if needed.
   If recurrent on a supported version, escalate as a likely bug.

.. _WSGI0038:

WSGI0038 — Python based handlers unavailable in process
-------------------------------------------------------

:Severity: ERR
:Source: ``src/server/wsgi_interp.c``

:Logged message:
   ``Python based handlers will not be available in
   <process-context>.`` Process context shape as for :ref:`WSGI0036`.

:Cause:
   ``newInterpreterObject(NULL)`` failed when creating the cached
   wrapper for the main Python interpreter at child / daemon
   startup. The cause and underlying Python exception are logged
   immediately above this entry by :ref:`WSGI0035` and the
   accompanying interpreter-init traceback (:ref:`WSGI0188` /
   :ref:`WSGI0189`); this entry records the operational consequence.

:Outcome:
   ``wsgi_python_initialized`` is set to 0 and the function returns
   ``APR_EGENERAL``. The child or daemon process cannot serve Python
   requests.

:Operator action:
   Read the preceding :ref:`WSGI0035` block and its traceback to
   identify the cause. Check free memory on the host. Reduce
   ``threads=`` or ``processes=`` on heavily configured daemon
   groups if the system is at memory pressure during Apache
   startup.

.. _WSGI0039:

WSGI0039 — Unable to register main Python interpreter wrapper
-------------------------------------------------------------

:Severity: CRIT
:Source: ``src/server/wsgi_interp.c``

:Logged message:
   ``Unable to register wrapper for main Python interpreter in
   interpreter cache in <process-context>; Python based handlers
   will not be available.`` Process context shape as for
   :ref:`WSGI0036`.

:Cause:
   ``PyDict_SetItemString()`` failed when adding the freshly created
   main-interpreter wrapper to mod_wsgi's interpreter cache. Almost
   always a Python heap allocation failure.

:Outcome:
   ``wsgi_python_initialized`` is set to 0 and the function returns
   ``APR_EGENERAL``. The child or daemon process cannot serve Python
   requests.

:Operator action:
   Same as :ref:`WSGI0038`.

.. _WSGI0040:

WSGI0040 — Unable to acquire Python sub-interpreter during daemon startup script preload
----------------------------------------------------------------------------------------

:Severity: CRIT
:Source: ``src/server/wsgi_interp.c``

:Logged message:
   ``Unable to acquire <interpreter-context> during daemon startup
   script preload; skipping import.`` The interpreter context is of
   the form ``main interpreter in embedded mode``, ``sub-interpreter
   '<name>' of daemon process '<group>'``, or any combination.

:Cause:
   ``wsgi_acquire_interpreter()`` returned ``NULL`` while a daemon
   process was preloading the WSGI scripts named on
   ``WSGIImportScript`` directives at startup. The most common upstream
   cause is that Python initialisation failed for this daemon (see
   :ref:`WSGI0028`) or sub-interpreter creation failed (see
   :ref:`WSGI0035`).

:Outcome:
   The current preload entry is skipped; the daemon attempts to
   continue with subsequent imports. If Python is broken globally,
   most or all preloads will fail in turn.

:Operator action:
   Look earlier in the log for whichever of :ref:`WSGI0028`,
   :ref:`WSGI0035`, :ref:`WSGI0036`, :ref:`WSGI0037`, :ref:`WSGI0038`,
   or :ref:`WSGI0039` was emitted first; it identifies the underlying
   cause.


.. _WSGI0041:

WSGI0041 — Location of WSGI user authentication script not provided
-------------------------------------------------------------------

:Severity: ERR
:Source: ``src/server/wsgi_auth.c``

:Logged message:
   ``Location of WSGI user authentication script not provided.``

:Cause:
   The Basic-auth password-check hook (``wsgi_check_password``) ran
   for an authenticated request but no ``WSGIAuthUserScript``
   directive was configured for the request's scope. Apache invoked
   mod_wsgi as the auth provider via ``AuthBasicProvider wsgi`` but
   mod_wsgi has no script to call.

:Outcome:
   The hook returns ``AUTH_GENERAL_ERROR``; Apache responds with
   500 Internal Server Error to the client.

:Operator action:
   Configure ``WSGIAuthUserScript`` for the scope (typically the
   ``<Location>`` or ``<Directory>`` that requires authentication),
   or remove the ``AuthBasicProvider wsgi`` directive if mod_wsgi is
   not the intended auth provider.

.. _WSGI0042:

WSGI0042 — Unable to acquire Python sub-interpreter for user authentication hook
--------------------------------------------------------------------------------

:Severity: ERR
:Source: ``src/server/wsgi_auth.c``

:Logged message:
   ``Unable to acquire <interpreter> for user authentication hook.``
   The interpreter is either ``main interpreter`` or ``sub-interpreter
   '<name>'``.

:Cause:
   ``wsgi_acquire_interpreter()`` returned ``NULL`` while the
   Basic-auth password-check hook (``wsgi_check_password``) was
   trying to enter the named interpreter. The most common upstream
   causes are: Python initialisation failed for this Apache child
   (see :ref:`WSGI0028`), or the sub-interpreter could not be
   created on demand (see :ref:`WSGI0103`).

:Outcome:
   The hook returns ``AUTH_GENERAL_ERROR``; Apache responds with
   500 Internal Server Error to the client.

:Operator action:
   Look earlier in the log for any prior Python-initialisation or
   sub-interpreter-creation failure in this daemon process; that
   identifies the underlying problem. If Python initialisation has
   succeeded, check for memory pressure on the host.

.. _WSGI0043:

WSGI0043 — Target WSGI user authentication script does not provide 'Basic' auth provider
----------------------------------------------------------------------------------------

:Severity: ERR
:Source: ``src/server/wsgi_auth.c``

:Logged message:
   ``Target WSGI user authentication script '<script>' does not
   provide 'Basic' auth provider.``

:Cause:
   The script loaded via ``WSGIAuthUserScript`` does not define a
   ``check_password(environ, user, password)`` callable in its
   module-global namespace. mod_wsgi looks up that name when Apache
   invokes the Basic auth provider.

:Outcome:
   The hook completes without an authentication outcome. Apache
   typically rejects the request as unauthorized.

:Operator action:
   Add a ``check_password`` function to the WSGI authentication
   script, or remove the ``AuthBasicProvider wsgi`` directive if the
   script is intended only for Digest auth or another purpose.

.. _WSGI0044:

WSGI0044 — Location of WSGI user authentication script not provided (Digest)
----------------------------------------------------------------------------

:Severity: ERR
:Source: ``src/server/wsgi_auth.c``

:Logged message:
   ``Location of WSGI user authentication script not provided.``

:Cause:
   The Digest-auth realm-hash hook (``wsgi_get_realm_hash``) ran
   but no ``WSGIAuthUserScript`` directive was configured for the
   request scope. Apache invoked mod_wsgi as the auth provider via
   ``AuthDigestProvider wsgi`` but mod_wsgi has no script to call.

:Outcome:
   The hook returns ``AUTH_GENERAL_ERROR``; Apache responds with
   500 Internal Server Error to the client.

:Operator action:
   Configure ``WSGIAuthUserScript`` for the scope, or remove the
   ``AuthDigestProvider wsgi`` directive if mod_wsgi is not the
   intended auth provider. (Same shape as :ref:`WSGI0041`.)

.. _WSGI0045:

WSGI0045 — Unable to acquire Python sub-interpreter for user authentication hook (Digest)
-----------------------------------------------------------------------------------------

:Severity: ERR
:Source: ``src/server/wsgi_auth.c``

:Logged message:
   ``Unable to acquire <interpreter> for user authentication hook.``
   The interpreter is either ``main interpreter`` or ``sub-interpreter
   '<name>'``.

:Cause:
   ``wsgi_acquire_interpreter()`` returned ``NULL`` while the
   Digest-auth realm-hash hook (``wsgi_get_realm_hash``) was trying
   to enter the named interpreter. Same upstream causes as
   :ref:`WSGI0042`.

:Outcome:
   The hook returns ``AUTH_GENERAL_ERROR``; Apache responds with
   500 Internal Server Error to the client.

:Operator action:
   Same as :ref:`WSGI0042`.

.. _WSGI0046:

WSGI0046 — Target WSGI user authentication script does not provide 'Digest' auth provider
-----------------------------------------------------------------------------------------

:Severity: ERR
:Source: ``src/server/wsgi_auth.c``

:Logged message:
   ``Target WSGI user authentication script '<script>' does not
   provide 'Digest' auth provider.``

:Cause:
   The script loaded via ``WSGIAuthUserScript`` does not define a
   ``get_realm_hash(environ, user, realm)`` callable. mod_wsgi looks
   up that name when Apache invokes the Digest auth provider.

:Outcome:
   The hook completes without an authentication outcome; Apache
   rejects the request as unauthorized.

:Operator action:
   Add a ``get_realm_hash`` function to the WSGI authentication
   script, or remove the ``AuthDigestProvider wsgi`` directive.

.. _WSGI0047:

WSGI0047 — Location of WSGI group authentication script not provided
--------------------------------------------------------------------

:Severity: ERR
:Source: ``src/server/wsgi_auth.c``

:Logged message:
   ``Location of WSGI group authentication script not provided.``

:Cause:
   ``wsgi_groups_for_user`` ran for the request but no
   ``WSGIAuthGroupScript`` directive was configured for the request
   scope.

:Outcome:
   ``HTTP_INTERNAL_SERVER_ERROR`` is returned to the caller;
   authorization for the request fails.

:Operator action:
   Configure ``WSGIAuthGroupScript`` for the scope.

.. _WSGI0048:

WSGI0048 — Unable to acquire Python sub-interpreter for group authentication hook
---------------------------------------------------------------------------------

:Severity: ERR
:Source: ``src/server/wsgi_auth.c``

:Logged message:
   ``Unable to acquire <interpreter> for group authentication hook.``
   The interpreter is either ``main interpreter`` or ``sub-interpreter
   '<name>'``.

:Cause:
   ``wsgi_acquire_interpreter()`` returned ``NULL`` while
   ``wsgi_groups_for_user`` was looking up the named interpreter.
   Same upstream causes as :ref:`WSGI0042`.

:Outcome:
   ``HTTP_INTERNAL_SERVER_ERROR`` is returned; authorization fails.

:Operator action:
   Same as :ref:`WSGI0042`.

.. _WSGI0049:

WSGI0049 — Item returned from groups_for_user contains non-latin-1 characters
-----------------------------------------------------------------------------

:Severity: ERR
:Source: ``src/server/wsgi_auth.c``

:Logged message:
   ``Item returned from 'groups_for_user' in '<script>' is a
   string containing characters that cannot be encoded as latin-1;
   expected a byte string.``

:Cause:
   ``groups_for_user(environ, user)`` returned an iterable whose
   items include a unicode string containing characters outside the
   latin-1 range. mod_wsgi attempts to encode unicode items as
   latin-1 to obtain bytes.

:Outcome:
   The current item is rejected; the iteration over groups stops
   and authorization fails with ``HTTP_INTERNAL_SERVER_ERROR``.

:Operator action:
   Ensure group names returned by ``groups_for_user`` are bytes
   (or ASCII-safe strings).

.. _WSGI0050:

WSGI0050 — Item returned from groups_for_user is not a byte string
------------------------------------------------------------------

:Severity: ERR
:Source: ``src/server/wsgi_auth.c``

:Logged message:
   ``Item returned from 'groups_for_user' in '<script>' is not a
   byte string.``

:Cause:
   ``groups_for_user(environ, user)`` returned an iterable whose
   items include a value that is neither a unicode string (handled
   by :ref:`WSGI0049`) nor a bytes object.

:Outcome:
   Iteration stops; authorization fails with
   ``HTTP_INTERNAL_SERVER_ERROR``.

:Operator action:
   Ensure ``groups_for_user`` returns an iterable of bytes objects
   (or ASCII strings).

.. _WSGI0051:

WSGI0051 — Result of groups_for_user is not iterable
----------------------------------------------------

:Severity: ERR
:Source: ``src/server/wsgi_auth.c``

:Logged message:
   ``Result returned from 'groups_for_user' in '<script>' is not
   iterable; expected an iterable sequence of byte strings.``

:Cause:
   The Python ``groups_for_user(environ, user)`` callable in the
   configured ``WSGIAuthGroupScript`` returned a value that does not
   support iteration (``PyObject_GetIter()`` failed). mod_wsgi
   expects the callable to return an iterable, typically a list or
   tuple, whose items are byte strings naming the groups the
   authenticated user belongs to.

:Outcome:
   Group lookup fails. ``wsgi_groups_for_user`` returns
   ``HTTP_INTERNAL_SERVER_ERROR`` to its caller; authorization for
   the request is denied.

:Operator action:
   Fix the application's ``groups_for_user`` callable so that it
   returns an iterable.

.. _WSGI0052:

WSGI0052 — Target WSGI group authentication script does not provide 'groups_for_user' callable
----------------------------------------------------------------------------------------------

:Severity: ERR
:Source: ``src/server/wsgi_auth.c``

:Logged message:
   ``Target WSGI group authentication script '<script>' does not
   provide 'groups_for_user' callable.``

:Cause:
   The script loaded via ``WSGIAuthGroupScript`` does not define a
   ``groups_for_user(environ, user)`` callable.

:Outcome:
   Authorization fails; ``HTTP_INTERNAL_SERVER_ERROR`` returned.

:Operator action:
   Add a ``groups_for_user`` function to the script.

.. _WSGI0053:

WSGI0053 — Location of WSGI host access script not provided
-----------------------------------------------------------

:Severity: ERR
:Source: ``src/server/wsgi_auth.c``

:Logged message:
   ``Location of WSGI host access script not provided.``

:Cause:
   ``wsgi_allow_access`` ran for the request but no
   ``WSGIAccessScript`` directive was configured for the scope.

:Outcome:
   The function returns 0 (deny); the request gets ``HTTP_FORBIDDEN``
   (403).

:Operator action:
   Configure ``WSGIAccessScript`` for the scope, or remove the
   host-access directive that triggers this hook.

.. _WSGI0054:

WSGI0054 — Unable to acquire Python sub-interpreter for host access hook
------------------------------------------------------------------------

:Severity: ERR
:Source: ``src/server/wsgi_auth.c``

:Logged message:
   ``Unable to acquire <interpreter> for host access hook.`` The
   interpreter is either ``main interpreter`` or ``sub-interpreter
   '<name>'``.

:Cause:
   ``wsgi_acquire_interpreter()`` returned ``NULL`` while
   ``wsgi_allow_access`` was looking up the named interpreter.
   Same upstream causes as :ref:`WSGI0042`.

:Outcome:
   Returns 0 (deny); the request gets 403.

:Operator action:
   Same as :ref:`WSGI0042`.

.. _WSGI0055:

WSGI0055 — Result of allow_access must be boolean or None
---------------------------------------------------------

:Severity: ERR
:Source: ``src/server/wsgi_auth.c``

:Logged message:
   ``Result returned from 'allow_access' in '<script>' must be a
   boolean or None.``

:Cause:
   The ``allow_access(environ, host)`` callable returned a value
   other than ``True``, ``False``, or ``None``.

:Outcome:
   The result is treated as deny; the request gets 403.

:Operator action:
   Fix ``allow_access`` to return a boolean or ``None``.

.. _WSGI0056:

WSGI0056 — Target WSGI host access script does not provide 'allow_access' callable
----------------------------------------------------------------------------------

:Severity: ERR
:Source: ``src/server/wsgi_auth.c``

:Logged message:
   ``Target WSGI host access script '<script>' does not provide
   'allow_access' callable.``

:Cause:
   The script loaded via ``WSGIAccessScript`` does not define an
   ``allow_access(environ, host)`` callable.

:Outcome:
   Access is denied; the request gets 403.

:Operator action:
   Add an ``allow_access`` function to the script.

.. _WSGI0057:

WSGI0057 — Client denied by server configuration
------------------------------------------------

:Severity: ERR
:Source: ``src/server/wsgi_auth.c``

:Logged message:
   ``Client denied by server configuration: '<filename>'.``

:Cause:
   The host-access check returned deny and the access-control
   configuration does not satisfy any other auth requirement (no
   ``Satisfy any`` fallback that would let authentication carry
   the request).

:Outcome:
   ``HTTP_FORBIDDEN`` (403) returned to the client.

:Operator action:
   This is the expected path for a denied request. Investigate
   only if the denial is unexpected; review the
   ``WSGIAccessScript`` and the request origin.

.. _WSGI0058:

WSGI0058 — Location of WSGI group authorization script not provided
-------------------------------------------------------------------

:Severity: ERR
:Source: ``src/server/wsgi_auth.c``

:Logged message:
   ``Location of WSGI group authorization script not provided.``

:Cause:
   The Apache authz provider hook
   (``wsgi_check_authorization``) ran when ``Require wsgi-group ...``
   was specified but no ``WSGIAuthGroupScript`` directive was
   configured.

:Outcome:
   ``AUTHZ_DENIED``.

:Operator action:
   Configure ``WSGIAuthGroupScript`` for the scope. This site is
   reached from the authz provider entry point; compare
   :ref:`WSGI0047` for the related authn-side error.

.. _WSGI0059:

WSGI0059 — Authorization failed: user is not a member of any groups
-------------------------------------------------------------------

:Severity: ERR
:Source: ``src/server/wsgi_auth.c``

:Logged message:
   ``Authorization of user '<user>' to access '<uri>' failed.
   User is not a member of any groups.``

:Cause:
   The authenticated user is not in any group returned by
   ``groups_for_user``.

:Outcome:
   ``AUTHZ_DENIED``.

:Operator action:
   Verify the user's group membership in the application's data
   source. Confirm the ``WSGIAuthGroupScript`` returns the expected
   groups for this user.

.. _WSGI0060:

WSGI0060 — Authorization failed: user not in designated groups
--------------------------------------------------------------

:Severity: ERR
:Source: ``src/server/wsgi_auth.c``

:Logged message:
   ``Authorization of user '<user>' to access '<uri>' failed.
   User is not a member of designated groups.``

:Cause:
   The authenticated user is in some groups, but none of them match
   the groups required by the ``Require wsgi-group ...`` directive.

:Outcome:
   ``AUTHZ_DENIED``.

:Operator action:
   Confirm the required groups against the user's actual
   memberships, or adjust the ``Require wsgi-group ...`` directive.

.. _WSGI0061:

WSGI0061 — Unable to set process dumpable flag in Apache child
--------------------------------------------------------------

:Severity: WARNING
:Source: ``src/server/wsgi_daemon.c``

:Logged message:
   ``Unable to set process dumpable flag in Apache child;
   coredumps will not be produced after software errors.``

:Cause:
   ``prctl(PR_SET_DUMPABLE, 1)`` failed when the Apache child was
   preparing for its configured ``CoreDumpDirectory``. Typically a
   kernel security policy prevents the call.

:Outcome:
   The Apache child runs normally; if it crashes, no coredump is
   written.

:Operator action:
   Verify ``CoreDumpDirectory`` is correctly configured and writable.
   The failure is uncommon and generally indicates a system-level
   policy.

.. _WSGI0062:

WSGI0062 — Unable to set send buffer size on daemon process socket
------------------------------------------------------------------

:Severity: WARNING
:Source: ``src/server/wsgi_daemon.c``

:Logged message:
   ``Unable to set send buffer size on daemon process socket;
   default size will be used.``

:Cause:
   ``setsockopt(SO_SNDBUF, ...)`` failed during daemon socket
   creation. The size requested via ``send-buffer-size=`` may
   exceed the system's maximum.

:Outcome:
   The daemon listener uses the default kernel send-buffer size.

:Operator action:
   Verify the requested size against ``sysctl net.core.wmem_max``
   (or the platform equivalent), or omit ``send-buffer-size=`` to
   use the kernel default.

.. _WSGI0063:

WSGI0063 — Unable to set receive buffer size on daemon process socket
---------------------------------------------------------------------

:Severity: WARNING
:Source: ``src/server/wsgi_daemon.c``

:Logged message:
   ``Unable to set receive buffer size on daemon process socket;
   default size will be used.``

:Cause:
   ``setsockopt(SO_RCVBUF, ...)`` failed during daemon socket
   creation. Same shape as :ref:`WSGI0062`.

:Outcome:
   The daemon listener uses the default kernel receive-buffer size.

:Operator action:
   Same as :ref:`WSGI0062`, against ``sysctl net.core.rmem_max``.

.. _WSGI0064:

WSGI0064 — Daemon process socket path will be truncated
-------------------------------------------------------

:Severity: WARNING
:Source: ``src/server/wsgi_daemon.c``

:Logged message:
   ``Length of path for daemon process socket exceeds maximum
   allowed value and will be truncated; the subsequent bind() is
   likely to fail.``

:Cause:
   The configured socket path is longer than
   ``sizeof(struct sockaddr_un.sun_path)`` (typically 108 chars on
   Linux, 104 on BSD).

:Outcome:
   The path is silently truncated to fit the structure. The
   ``bind()`` at :ref:`WSGI0013` will fail unless the truncated
   path happens to be valid and unique.

:Operator action:
   Set ``WSGISocketPrefix`` to a shorter directory, or use a
   shorter daemon group name.

.. _WSGI0065:

WSGI0065 — Removing stale unix domain socket before re-binding
--------------------------------------------------------------

:Severity: WARNING
:Source: ``src/server/wsgi_daemon.c``

:Logged message:
   ``Removing stale unix domain socket '<path>' before re-binding
   daemon process listener.``

:Cause:
   ``bind()`` returned ``EADDRINUSE`` on the daemon's unix socket
   path. mod_wsgi unlinks the stale socket and retries ``bind()``.
   Typically happens after a previous Apache instance failed to
   clean up at exit.

:Outcome:
   The stale socket is unlinked and ``bind()`` is retried. If the
   retry succeeds, the daemon comes up normally.

:Operator action:
   No immediate action required if the daemon comes up. Recurring
   occurrences indicate Apache is not shutting down cleanly; review
   the parent process for crashes or kills.

.. _WSGI0066:

WSGI0066 — Unable to iterate over current frames for active threads
-------------------------------------------------------------------

:Severity: WARNING
:Source: ``src/server/wsgi_daemon.c``

:Logged message:
   ``Unable to iterate over current frames for active threads;
   stack-trace dump will be incomplete.``

:Cause:
   ``PyObject_GetIter`` on the dict returned by
   ``sys._current_frames()`` failed during the deadlock-thread
   stack-trace dump.

:Outcome:
   Some thread stacks may be missing from the diagnostic dump.

:Operator action:
   Generally none; the dump is a best-effort diagnostic aid emitted
   on shutdown timeout.

.. _WSGI0067:

WSGI0067 — Unable to obtain current frames for active threads
-------------------------------------------------------------

:Severity: WARNING
:Source: ``src/server/wsgi_daemon.c``

:Logged message:
   ``Unable to obtain current frames for active threads;
   stack-trace dump will be skipped.``

:Cause:
   ``sys._current_frames()`` returned ``NULL``.

:Outcome:
   The stack-trace dump is skipped entirely.

:Operator action:
   Same as :ref:`WSGI0066`.

.. _WSGI0068:

WSGI0068 — Unable to create monitor thread in daemon process
------------------------------------------------------------

:Severity: ERR
:Source: ``src/server/wsgi_daemon.c``

:Logged message:
   ``Unable to create monitor thread in daemon process '<group>';
   request and idle timeouts will not be enforced.``

:Cause:
   ``apr_thread_create()`` failed when the daemon was spawning the
   monitor thread. Usually thread-limit pressure on the daemon's
   user.

:Outcome:
   The daemon runs but ``request-time-limit``,
   ``inactivity-timeout``, ``startup-timeout``, and similar timeout
   settings are not enforced. The daemon group otherwise functions.

:Operator action:
   Investigate thread/process limits for the daemon's user.
   Restart the affected daemon group if these timeouts are
   operationally critical.

.. _WSGI0069:

WSGI0069 — Unable to create deadlock-detection thread in daemon process
-----------------------------------------------------------------------

:Severity: ERR
:Source: ``src/server/wsgi_daemon.c``

:Logged message:
   ``Unable to create deadlock-detection thread in daemon process
   '<group>'; deadlock timeouts will not be enforced.``

:Cause:
   ``apr_thread_create()`` failed for the deadlock-detection
   thread.

:Outcome:
   The daemon runs but the ``deadlock-timeout=`` setting is not
   enforced.

:Operator action:
   Same as :ref:`WSGI0068`.

.. _WSGI0070:

WSGI0070 — Unable to create reaper thread during daemon shutdown
----------------------------------------------------------------

:Severity: WARNING
:Source: ``src/server/wsgi_daemon.c``

:Logged message:
   ``Unable to create reaper thread in daemon process '<group>';
   shutdown timeout will not be enforced.``

:Cause:
   ``apr_thread_create()`` failed while the daemon process was
   spawning the reaper thread during graceful shutdown. The reaper
   thread aborts the daemon process if shutdown does not complete
   within the configured ``shutdown-timeout``.

:Outcome:
   Daemon shutdown proceeds without the forced-abort timer. If the
   daemon hangs during graceful shutdown it will not be aborted by
   mod_wsgi; Apache or an external supervisor must terminate it.

:Operator action:
   No immediate action required for normal shutdowns. If a daemon
   hangs at shutdown after this warning fires, ``kill`` it manually;
   investigate the underlying APR error code (memory or thread-limit
   pressure) reported in the log line.

.. _WSGI0071:

WSGI0071 — Unable to join with worker thread during shutdown
------------------------------------------------------------

:Severity: WARNING
:Source: ``src/server/wsgi_daemon.c``

:Logged message:
   ``Unable to join with worker thread <N> in daemon process
   '<group>' during shutdown.``

:Cause:
   ``apr_thread_join()`` failed during graceful shutdown; the
   thread is in an unknown state.

:Outcome:
   Shutdown proceeds; the thread is left for the OS to reap when
   the process exits.

:Operator action:
   No action required — the daemon is exiting.

.. _WSGI0072:

WSGI0072 — Unable to close unix domain socket during cleanup
------------------------------------------------------------

:Severity: WARNING
:Source: ``src/server/wsgi_daemon.c``

:Logged message:
   ``Unable to close unix domain socket '<path>' during daemon
   process group cleanup.``

:Cause:
   ``close(fd)`` failed during Apache parent-side cleanup of a
   daemon group's listener socket.

:Outcome:
   The socket is left open in the parent; resources are reclaimed
   when the parent exits.

:Operator action:
   No action required.

.. _WSGI0073:

WSGI0073 — Unable to unlink unix domain socket during cleanup
-------------------------------------------------------------

:Severity: WARNING
:Source: ``src/server/wsgi_daemon.c``

:Logged message:
   ``Unable to unlink unix domain socket '<path>' during daemon
   process group cleanup.``

:Cause:
   ``unlink()`` of the daemon's socket file failed during Apache
   parent-side cleanup. Common when the socket file was already
   removed (for example by stale-socket cleanup at
   :ref:`WSGI0065`).

:Outcome:
   A leftover socket file may remain on disk.

:Operator action:
   No action required if Apache restarts cleanly. Manually remove
   the file if it is left behind and a new ``bind()`` fails.

.. _WSGI0074:

WSGI0074 — Unable to unbind processor for daemon process
--------------------------------------------------------

:Severity: WARNING
:Source: ``src/server/wsgi_daemon.c``

:Logged message:
   ``Unable to unbind processor for daemon process; daemon will
   run with default CPU affinity.``

:Cause:
   ``bindprocessor(BINDPROCESS, ...)`` failed (AIX-specific
   syscall used to release Apache's CPU binding before daemon
   initialisation).

:Outcome:
   The daemon runs with whatever CPU affinity it inherited from
   Apache.

:Operator action:
   Generally no action required; mostly relevant on AIX.

.. _WSGI0075:

WSGI0075 — Unable to set CPU priority for daemon process
--------------------------------------------------------

:Severity: WARNING
:Source: ``src/server/wsgi_daemon.c``

:Logged message:
   ``Unable to set CPU priority of <N> for daemon process
   '<group>'; daemon will run with default priority.``

:Cause:
   ``setpriority(PRIO_PROCESS, 0, N)`` failed. Most common causes:
   insufficient privilege to lower the niceness, or the requested
   value is outside the allowed range.

:Outcome:
   The daemon runs at default CPU priority.

:Operator action:
   Verify the user the daemon runs as has permission to set the
   requested priority; typically only root can lower nice values
   below 0. Adjust ``cpu-priority=`` if outside the allowed range.

.. _WSGI0076:

WSGI0076 — Unable to set CPU time limit for daemon process
----------------------------------------------------------

:Severity: WARNING
:Source: ``src/server/wsgi_daemon.c``

:Logged message:
   ``Unable to set CPU time limit of <N> seconds for daemon process
   '<group>'; daemon will run without the configured limit.``

:Cause:
   ``setrlimit(RLIMIT_CPU, ...)`` failed when the daemon was
   applying the ``cpu-time-limit=`` directive. Either the platform
   does not support ``RLIMIT_CPU``, the requested limit exceeds the
   system-imposed hard limit for the daemon's user, or another
   OS-level constraint blocked the call.

:Outcome:
   The daemon continues running without a CPU time limit. The
   ``cpu-time-limit=`` directive has no effect for this process.

:Operator action:
   Verify the requested limit against the system's hard limit (for
   the user the daemon runs as) using ``ulimit -t`` or
   ``/etc/security/limits.conf``. Lower ``cpu-time-limit=`` if the
   system disallows the requested value, or remove the directive if
   the platform does not support ``RLIMIT_CPU``.

.. _WSGI0077:

WSGI0077 — Unable to set memory limit for daemon process
--------------------------------------------------------

:Severity: WARNING
:Source: ``src/server/wsgi_daemon.c``

:Logged message:
   ``Unable to set memory limit of <N> for daemon process
   '<group>'; daemon will run without the configured limit.``

:Cause:
   ``setrlimit(RLIMIT_DATA, ...)`` failed when the daemon was
   applying the ``memory-limit=`` directive.

:Outcome:
   The daemon runs without the configured memory limit.

:Operator action:
   Verify the requested limit against system constraints.
   ``RLIMIT_DATA`` semantics vary by OS; consider
   ``virtual-memory-limit=`` as an alternative.

.. _WSGI0078:

WSGI0078 — Unable to set virtual memory limit for daemon process
----------------------------------------------------------------

:Severity: WARNING
:Source: ``src/server/wsgi_daemon.c``

:Logged message:
   ``Unable to set virtual memory limit of <N> for daemon process
   '<group>'; daemon will run without the configured limit.``

:Cause:
   ``setrlimit(RLIMIT_AS, ...)`` (or ``RLIMIT_VMEM`` where
   available) failed when the daemon was applying the
   ``virtual-memory-limit=`` directive.

:Outcome:
   The daemon runs without the configured virtual memory limit.

:Operator action:
   Same as :ref:`WSGI0077`.

.. _WSGI0079:

WSGI0079 — Unsupported locale setting for daemon process group
--------------------------------------------------------------

:Severity: WARNING
:Source: ``src/server/wsgi_daemon.c``

:Logged message:
   ``Unsupported locale setting '<locale>' specified for daemon
   process group '<group>'; daemon will run with the inherited
   locale. Consider 'C.UTF-8' as a fallback.``

:Cause:
   ``setlocale(LC_ALL, ...)`` returned ``NULL`` for the configured
   ``locale=``. The locale data may be missing on the system, or
   the locale name may be misspelled.

:Outcome:
   The daemon runs with whatever locale it inherited from Apache
   (typically C / POSIX).

:Operator action:
   Install the requested locale (for example via ``locale-gen`` on
   Debian/Ubuntu), correct the locale name, or use ``C.UTF-8``
   which is universally available on Linux.

.. _WSGI0080:

WSGI0080 — Unable to read incoming WSGI request from Apache child
-----------------------------------------------------------------

:Severity: ERR
:Source: ``src/server/wsgi_daemon.c``

:Logged message:
   ``Unable to read incoming WSGI request from Apache child;
   request will be aborted with 500.``

:Cause:
   ``wsgi_read_request()`` failed to deserialise the incoming
   request envelope from the Apache child over the unix socket.
   Typically a transient network or socket error; very occasionally
   a malformed request.

:Outcome:
   The daemon worker logs the error, destroys the request pool,
   and returns ``HTTP_INTERNAL_SERVER_ERROR`` to the Apache child.

:Operator action:
   Generally none — this is per-request. If the failure is
   sustained, investigate the unix socket or Apache child health.

.. _WSGI0081:

WSGI0081 — WSGI script not located within chroot directory
----------------------------------------------------------

:Severity: ERR
:Source: ``src/server/wsgi_daemon.c``

:Logged message:
   ``WSGI script '<path>' is not located within chroot directory
   '<root>'; rejecting request.``

:Cause:
   When the daemon is configured with ``chroot=``, the
   ``SCRIPT_FILENAME`` passed by Apache must lie within the chroot
   tree. This request's filename does not.

:Outcome:
   The request is rejected with ``HTTP_INTERNAL_SERVER_ERROR``
   (500).

:Operator action:
   Move the WSGI script under the chroot, or remove the
   ``chroot=`` option if not required for the deployment.

.. _WSGI0082:

WSGI0082 — Unable to stat target handler script
------------------------------------------------

:Severity: WARNING
:Source: ``src/server/wsgi_daemon.c``

:Logged message:
   ``Unable to stat target handler script '<script>'.``

:Cause:
   ``apr_stat()`` failed on the ``WSGIHandlerScript`` path. The
   file may have been removed, renamed, or its directory may be
   unreadable for the daemon's user.

:Outcome:
   The request continues to the script-load step where the missing
   file will be detected; ``mtime`` is set to 0.

:Operator action:
   Verify the file exists and is readable by the daemon's user.
   Check the ``WSGIHandlerScript`` directive.

.. _WSGI0083:

WSGI0083 — Unable to stat target WSGI script
--------------------------------------------

:Severity: WARNING
:Source: ``src/server/wsgi_daemon.c``

:Logged message:
   ``Unable to stat target WSGI script '<filename>'.``

:Cause:
   ``apr_stat()`` failed on the WSGI script path
   (``SCRIPT_FILENAME``). Same shape as :ref:`WSGI0082`.

:Outcome:
   The request continues; ``mtime`` is set to 0.

:Operator action:
   Same as :ref:`WSGI0082`.

.. _WSGI0084:

WSGI0084 — Queue timeout expired for WSGI daemon process
--------------------------------------------------------

:Severity: ERR
:Source: ``src/server/wsgi_daemon.c``

:Logged message:
   ``Queue timeout expired for WSGI daemon process '<group>'.``

:Cause:
   The request waited in the daemon's accept queue longer than
   ``queue-timeout=``. The daemon worker dequeued it but rejects
   it because it has aged beyond the configured threshold.

:Outcome:
   The request is returned to the Apache child via a
   ``200 Timeout`` status header; the Apache child responds with
   ``HTTP_GATEWAY_TIME_OUT`` (504).

:Operator action:
   Investigate request rate vs. configured ``threads=`` and
   ``processes=``. ``queue-timeout=`` should be set so that aged
   requests are rejected rather than served slowly; raising threads
   or processes typically reduces queue depth.

.. _WSGI0085:

WSGI0085 — Location of WSGI dispatch script not provided
--------------------------------------------------------

:Severity: ERR
:Source: ``src/server/wsgi_dispatch.c``

:Logged message:
   ``Location of WSGI dispatch script not provided.``

:Cause:
   A request was routed through the dispatch hook but no
   ``WSGIDispatchScript`` directive was configured.

:Outcome:
   ``HTTP_INTERNAL_SERVER_ERROR``.

:Operator action:
   Configure ``WSGIDispatchScript`` for the scope, or remove the
   directive that routes through the dispatch hook.

.. _WSGI0086:

WSGI0086 — Unable to acquire Python sub-interpreter for dispatch hook
---------------------------------------------------------------------

:Severity: ERR
:Source: ``src/server/wsgi_dispatch.c``

:Logged message:
   ``Unable to acquire <interpreter> for dispatch hook.`` The
   interpreter is either ``main interpreter`` or ``sub-interpreter
   '<name>'``.

:Cause:
   ``wsgi_acquire_interpreter()`` returned ``NULL`` while the
   dispatch hook was looking up the named interpreter. Same
   upstream causes as :ref:`WSGI0042`.

:Outcome:
   ``HTTP_INTERNAL_SERVER_ERROR``.

:Operator action:
   Same as :ref:`WSGI0042`.

.. _WSGI0087:

WSGI0087 — Unable to acquire Python sub-interpreter for WSGI request handler
----------------------------------------------------------------------------

:Severity: ERR
:Source: ``src/server/wsgi_execute.c``

:Logged message:
   ``Unable to acquire <interpreter> for WSGI request handler in
   <process-context>.`` The interpreter is either ``main
   interpreter`` or ``sub-interpreter '<name>'``; the process
   context is either ``embedded mode`` or ``daemon process
   '<group>'``.

:Cause:
   ``wsgi_acquire_interpreter()`` returned ``NULL`` at the main
   WSGI request-handling entry point. Same upstream causes as
   :ref:`WSGI0042`.

:Outcome:
   ``HTTP_INTERNAL_SERVER_ERROR`` (500) returned to the client.

:Operator action:
   Same as :ref:`WSGI0042`.

.. _WSGI0088:

WSGI0088 — Unable to import handler via Python module reference
---------------------------------------------------------------

:Severity: ERR
:Source: ``src/server/wsgi_execute.c``

:Logged message:
   ``Unable to import handler via Python module reference
   '<script>'.``

:Cause:
   A ``WSGIHandlerScript`` value of the form ``(module.name)``
   could not be imported.

:Outcome:
   The corresponding request fails with logged Python error and
   ``HTTP_INTERNAL_SERVER_ERROR``.

:Operator action:
   This code path is currently disabled at compile time
   (``#if 0`` in the source); the entry is allocated for future
   use.

.. _WSGI0089:

WSGI0089 — Target WSGI script does not contain WSGI application
---------------------------------------------------------------

:Severity: ERR
:Source: ``src/server/wsgi_execute.c``

:Logged message:
   ``Target WSGI script '<script>' does not contain WSGI
   application '<callable>'.``

:Cause:
   The loaded WSGI script module does not define the named
   callable (default ``application``). The callable name is set by
   ``WSGICallableObject`` or per-script configuration.

:Outcome:
   The request returns ``HTTP_NOT_FOUND`` (404).

:Operator action:
   Verify the WSGI script defines the expected callable. Check
   the ``WSGICallableObject`` directive.

.. _WSGI0090:

WSGI0090 — signal.signal call failed when registering exit-function callback
----------------------------------------------------------------------------

:Severity: ERR
:Source: ``src/server/wsgi_interp.c``

:Logged message:
   ``Call to 'signal.signal()' to register exit-function callback
   failed for <interpreter-context> in <process-context>; continuing
   without callback.`` Interpreter context is ``main interpreter`` or
   ``sub-interpreter '<name>'``; process context is ``embedded mode``
   or ``daemon process '<group>'``.

:Cause:
   ``PyObject_CallObject`` on ``signal.signal()`` returned ``NULL``
   during interpreter setup of a service-script daemon (a daemon
   group with ``threads=0``). Almost always indicates a corrupted
   Python state or an unusual import-time state of the ``signal``
   module.

:Outcome:
   SIGTERM-driven graceful shutdown of Python ``atexit`` functions
   will not run when the daemon receives SIGTERM. Daemon otherwise
   functions.

:Operator action:
   Look earlier in the log for any Python error during interpreter
   initialisation. If the failure repeats across daemon restarts,
   the embedded Python is broken.

.. _WSGI0091:

WSGI0091 — Call to site.addsitedir() failed
-------------------------------------------

:Severity: ERR
:Source: ``src/server/wsgi_interp.c``

:Logged message:
   ``Call to 'site.addsitedir()' failed for '<path>' in
   <process-context>; remaining python-path entries will not be
   added.`` Process context is either ``embedded mode`` or
   ``daemon process '<group>'``.

:Cause:
   When applying a ``WSGIPythonPath`` / ``python-path=`` directive,
   mod_wsgi calls ``site.addsitedir()`` once per delim-separated
   entry. One of the calls failed — typically a missing or
   unreadable directory, a malformed ``.pth`` file, or a permission
   issue. The actual Python exception is logged immediately after
   this entry as :ref:`WSGI0188`.

:Outcome:
   Iteration over the path stops on first failure. The failed entry
   and any remaining entries are not added to ``sys.path``. Imports
   that depend on those entries will fail at runtime.

:Operator action:
   Read the accompanying :ref:`WSGI0188` traceback for the actual
   failure. Verify the named entry exists, is a directory, and is
   readable by the daemon's user.

.. _WSGI0092:

WSGI0092 — (retired)
--------------------

Previously logged a separate code for failures on subsequent
``python-path=`` entries. Consolidated into :ref:`WSGI0091`, which
now covers all addsitedir failures regardless of which entry was
being processed.

.. _WSGI0093:

WSGI0093 — (retired)
--------------------

Previously logged a separate code for failure on the final
``python-path=`` entry. Consolidated into :ref:`WSGI0091`.

.. _WSGI0094:

WSGI0094 — Unable to locate site.addsitedir
-------------------------------------------

:Severity: ERR
:Source: ``src/server/wsgi_interp.c``

:Logged message:
   ``Unable to locate 'site.addsitedir()' in <process-context>.``
   Process context shape as for :ref:`WSGI0091`.

:Cause:
   The ``site`` module was imported but does not expose
   ``addsitedir``. Almost always means a non-stdlib ``site.py`` was
   loaded by the embedded Python.

:Outcome:
   ``python-path=`` entries are not added to ``sys.path``.

:Operator action:
   Verify nothing in the application has shadowed the stdlib
   ``site`` module. Investigate the Python import path.

.. _WSGI0095:

WSGI0095 — Unable to import 'site' module
-----------------------------------------

:Severity: ERR
:Source: ``src/server/wsgi_interp.c``

:Logged message:
   ``Unable to import 'site' module in <process-context>.``
   Process context shape as for :ref:`WSGI0091`.

:Cause:
   ``PyImport_ImportModule("site")`` failed. Indicates a deeply
   broken Python installation.

:Outcome:
   ``python-path=`` entries are not added; ``sys.path`` may be
   missing common entries.

:Operator action:
   Verify the Python installation. Reproduce with
   ``python -c 'import site'`` from the daemon's user.

.. _WSGI0096:

WSGI0096 — Unable to look up sys.path attribute
------------------------------------------------

:Severity: ERR
:Source: ``src/server/wsgi_interp.c``

:Logged message:
   ``Unable to look up 'sys.path' attribute on 'sys' module in
   <process-context>.`` Process context shape as for :ref:`WSGI0091`.

:Cause:
   ``PyObject_GetAttrString(sys, "path")`` failed. Highly unusual;
   indicates a broken Python state.

:Outcome:
   ``python-path=`` entries are not added.

:Operator action:
   Verify the Python installation.

.. _WSGI0097:

WSGI0097 — SystemExit from Python atexit functions ignored
----------------------------------------------------------

:Severity: ERR
:Source: ``src/server/wsgi_logger.c``

:Logged message:
   ``SystemExit (<type>) raised by Python atexit functions during
   shutdown of <interpreter-context>; ignored.`` Interpreter context
   is of the form ``main interpreter in embedded mode`` or
   ``sub-interpreter '<name>' of daemon process '<group>'``.

:Cause:
   A Python ``atexit``-registered function raised ``SystemExit``
   during interpreter shutdown. mod_wsgi swallows the exception so
   it does not propagate further. The traceback is emitted as
   continuation lines after this header.

:Outcome:
   Interpreter shutdown continues; subsequent ``atexit`` handlers
   still run.

:Operator action:
   Investigate the application's ``atexit`` handlers; raising
   ``SystemExit`` from them is generally a bug.

.. _WSGI0098:

WSGI0098 — Exception within Python atexit functions during shutdown
-------------------------------------------------------------------

:Severity: ERR
:Source: ``src/server/wsgi_logger.c``

:Logged message:
   ``Exception (<type>) raised by Python atexit functions during
   shutdown of <interpreter-context>.`` Interpreter context shape as
   for :ref:`WSGI0097`.

:Cause:
   An ``atexit`` handler raised a non-``SystemExit`` exception. The
   traceback is emitted as continuation lines after this header.

:Outcome:
   Interpreter shutdown continues.

:Operator action:
   Investigate the offending ``atexit`` handler in the application.

.. _WSGI0099:

WSGI0099 — Compile-vs-runtime Python version mismatch
-----------------------------------------------------

:Severity: WARNING
:Source: ``src/server/wsgi_interp.c``

:Logged message:
   ``Compiled for Python/<X> but runtime using Python/<Y> in
   <process-context>.`` The process context is either ``embedded
   mode`` or ``daemon process '<group>'``.

:Cause:
   The Python version mod_wsgi was compiled against differs from
   the version dynamically linked at runtime. Running with a
   mismatch can produce subtle ABI failures.

:Outcome:
   Apache continues to start; mod_wsgi runs with the runtime
   Python.

:Operator action:
   Rebuild mod_wsgi against the runtime Python, or arrange the
   deployment so the linked-at-build Python matches the runtime
   Python.

.. _WSGI0100:

WSGI0100 — Unable to stat Python home
-------------------------------------

:Severity: WARNING
:Source: ``src/server/wsgi_interp.c``

:Logged message:
   ``Unable to stat Python home '<path>' for <process-context>;
   Python interpreter may not initialise correctly. Verify the
   path and the access permissions on every component of it.``
   Process context shape as for :ref:`WSGI0099`.

:Cause:
   ``apr_stat()`` on the configured Python home (``WSGIPythonHome``
   / ``python-home=``) failed.

:Outcome:
   Python initialisation will likely fail downstream.

:Operator action:
   Verify the path exists and every component is readable by the
   daemon's user.

.. _WSGI0101:

WSGI0101 — Python home is not a directory
-----------------------------------------

:Severity: WARNING
:Source: ``src/server/wsgi_interp.c``

:Logged message:
   ``Python home '<path>' for <process-context> is not a directory;
   Python interpreter may not initialise correctly. Verify the
   supplied path.`` Process context shape as for :ref:`WSGI0099`.

:Cause:
   The configured Python home points to a file or other
   non-directory entry. Common when ``WSGIPythonHome`` accidentally
   points at the python executable.

:Outcome:
   Python initialisation will likely fail downstream.

:Operator action:
   Set ``WSGIPythonHome`` to the prefix directory of the Python
   installation, not the executable or library file.

.. _WSGI0102:

WSGI0102 — Python home is not accessible
----------------------------------------

:Severity: WARNING
:Source: ``src/server/wsgi_interp.c``

:Logged message:
   ``Python home '<path>' for <process-context> is not accessible;
   Python interpreter may not initialise correctly. Verify the
   access permissions on the directory.`` Process context shape
   as for :ref:`WSGI0099`.

:Cause:
   ``access(path, X_OK)`` failed for the configured Python home.

:Outcome:
   Python initialisation will likely fail downstream.

:Operator action:
   Verify the daemon's user has execute (search) permission on the
   Python home directory.

.. _WSGI0103:

WSGI0103 — Python based handlers unavailable for sub-interpreter
----------------------------------------------------------------

:Severity: ERR
:Source: ``src/server/wsgi_interp.c``

:Logged message:
   ``Python based handlers will not be available for
   <interpreter-context> in <process-context>.`` Interpreter context
   is ``main interpreter`` or ``sub-interpreter '<name>'``; process
   context is ``embedded mode`` or ``daemon process '<group>'``.

:Cause:
   ``newInterpreterObject()`` returned ``NULL`` while
   ``wsgi_acquire_interpreter()`` was lazily creating the named
   sub-interpreter on the first request that needed it. The cause
   and underlying Python exception are logged immediately above this
   entry by :ref:`WSGI0035` and the accompanying interpreter-init
   traceback (:ref:`WSGI0188` / :ref:`WSGI0189`); this entry records
   the operational consequence.

:Outcome:
   ``wsgi_acquire_interpreter()`` returns ``NULL``. The caller
   (typically an auth or dispatch hook) returns 500 to the client.
   Subsequent requests for the same sub-interpreter will retry
   creation.

:Operator action:
   Read the preceding :ref:`WSGI0035` block and its traceback to
   identify the cause. Check free memory on the host. If the
   failure repeats, look for any preceding :ref:`WSGI0001` or
   :ref:`WSGI0028` message indicating the embedded interpreter is
   broken.

.. _WSGI0104:

WSGI0104 — Unable to publish process_stopping event
---------------------------------------------------

:Severity: ERR
:Source: ``src/server/wsgi_interp.c``

:Logged message:
   ``Unable to publish 'process_stopping' event for
   <interpreter-context>.`` Interpreter context is of the form
   ``main interpreter in embedded mode`` or ``sub-interpreter
   '<name>' of daemon process '<group>'``.

:Cause:
   Building the event dict for the ``process_stopping`` callback
   chain failed (``PyDict_New`` / ``PyDict_SetItemString`` /
   ``PyUnicode_DecodeLatin1`` returned ``NULL``). Almost always
   memory exhaustion during shutdown.

:Outcome:
   Subscribers to the ``process_stopping`` event do not run for
   this interpreter; shutdown otherwise proceeds.

:Operator action:
   Investigate memory pressure on the host. If the failure is
   repeatable, instrument or reduce the memory footprint of
   ``process_stopping`` subscribers.

.. _WSGI0105:

WSGI0105 — Could not read or compile WSGI script (request context)
------------------------------------------------------------------

:Severity: ERR
:Source: ``src/server/wsgi_interp.c``

:Logged message:
   ``Could not read or compile WSGI script '<filename>' for
   <interpreter-context>.`` The interpreter context is of the form
   ``main interpreter in embedded mode`` or ``sub-interpreter
   '<app>' of daemon process '<group>'``.

:Cause:
   ``io.open()`` of the script file failed, or
   ``Py_CompileString()`` raised ``SyntaxError`` or similar. The
   Python error for compile-time issues is logged immediately
   after.

:Outcome:
   Module load returns ``NULL``; the request fails with
   ``HTTP_INTERNAL_SERVER_ERROR``.

:Operator action:
   Check the Python error logged after this message for the
   specific cause. Verify file permissions and syntax.

.. _WSGI0106:

WSGI0106 — Could not read or compile WSGI script (server context)
-----------------------------------------------------------------

:Severity: ERR
:Source: ``src/server/wsgi_interp.c``

:Logged message:
   ``Could not read or compile WSGI script '<filename>' for
   <interpreter-context>.`` Interpreter context shape as for
   :ref:`WSGI0105`.

:Cause:
   Same as :ref:`WSGI0105` but emitted from a non-request context
   (typically ``WSGIImportScript`` at daemon startup).

:Outcome:
   Module load returns ``NULL``; the script preload is skipped.

:Operator action:
   Same as :ref:`WSGI0105`.

.. _WSGI0107:

WSGI0107 — SystemExit during Python script exec (request context)
-----------------------------------------------------------------

:Severity: ERR
:Source: ``src/server/wsgi_interp.c``

:Logged message:
   ``SystemExit exception raised when doing exec of Python script
   file '<filename>'.``

:Cause:
   The script raised ``SystemExit`` during execution at
   module-import time.

:Outcome:
   Module load returns ``NULL``; the request fails with
   ``HTTP_INTERNAL_SERVER_ERROR``.

:Operator action:
   Investigate the script for ``SystemExit`` raises during module
   top-level execution.

.. _WSGI0108:

WSGI0108 — SystemExit during Python script exec (server context)
----------------------------------------------------------------

:Severity: ERR
:Source: ``src/server/wsgi_interp.c``

:Logged message:
   ``SystemExit exception raised when doing exec of Python script
   file '<filename>'.``

:Cause:
   Same as :ref:`WSGI0107` but from a non-request context
   (typically ``WSGIImportScript`` at startup).

:Outcome:
   Module load returns ``NULL``; the script preload is skipped.

:Operator action:
   Same as :ref:`WSGI0107`.

.. _WSGI0109:

WSGI0109 — Unable to execute Python script file (request context)
-----------------------------------------------------------------

:Severity: ERR
:Source: ``src/server/wsgi_interp.c``

:Logged message:
   ``Unable to execute Python script file '<filename>'.``

:Cause:
   ``PyImport_ExecCodeModuleEx()`` returned ``NULL`` — the script
   raised an unhandled exception during top-level execution. The
   Python traceback is logged immediately after.

:Outcome:
   Module load returns ``NULL``; the request fails.

:Operator action:
   Inspect the Python traceback that follows for the actual cause.

.. _WSGI0110:

WSGI0110 — Unable to execute Python script file (server context)
----------------------------------------------------------------

:Severity: ERR
:Source: ``src/server/wsgi_interp.c``

:Logged message:
   ``Unable to execute Python script file '<filename>'.``

:Cause:
   Same as :ref:`WSGI0109` from a non-request context.

:Outcome:
   Module load returns ``NULL``; the script preload is skipped.

:Operator action:
   Same as :ref:`WSGI0109`.

.. _WSGI0111:

WSGI0111 — Main interpreter reference missing during child cleanup
------------------------------------------------------------------

:Severity: WARNING
:Source: ``src/server/wsgi_interp.c``

:Logged message:
   ``Main interpreter reference is missing from interpreters
   dictionary during cleanup in <process-context>.`` Process
   context is either ``embedded mode`` or ``daemon process
   '<group>'``.

:Cause:
   The cached ``""`` key is missing from mod_wsgi's interpreters
   dictionary at child-cleanup time. Indicates a state-corruption
   bug or unusual shutdown order.

:Outcome:
   Interpreter cleanup proceeds; the missing main wrapper means
   the main interpreter's exit functions are not driven through
   mod_wsgi's normal path.

:Operator action:
   No immediate action. If the message recurs, file an issue with
   reproduction details.

.. _WSGI0112:

WSGI0112 — Exception within event callback
------------------------------------------

:Severity: ERR
:Source: ``src/server/wsgi_metrics.c``

:Logged message:
   ``Exception occurred within event callback.``

:Cause:
   A subscriber registered via mod_wsgi's event-publish API raised
   an exception when the corresponding event fired.

:Outcome:
   The exception is logged with traceback; remaining subscribers
   continue to run.

:Operator action:
   Investigate the offending event subscriber. Identify it via the
   traceback that follows.

.. _WSGI0113:

WSGI0113 — Unable to import mod_wsgi when publishing events
-----------------------------------------------------------

:Severity: ERR
:Source: ``src/server/wsgi_metrics.c``

:Logged message:
   ``Unable to import mod_wsgi when publishing events.``

:Cause:
   ``PyImport_ImportModule("mod_wsgi")`` failed during event
   publication. Indicates a broken Python state.

:Outcome:
   The event is not dispatched; subscribers do not run.

:Operator action:
   Investigate Python import-state issues; the embedded interpreter
   may be broken.

.. _WSGI0114:

WSGI0114 — Unable to find event subscribers
-------------------------------------------

:Severity: ERR
:Source: ``src/server/wsgi_metrics.c``

:Logged message:
   ``Unable to find event subscribers.``

:Cause:
   The ``mod_wsgi`` module was imported but its
   ``event_callbacks`` / ``shutdown_callbacks`` dicts are not
   present. Indicates corrupted mod_wsgi internal state.

:Outcome:
   The event is not dispatched.

:Operator action:
   Same as :ref:`WSGI0113`.

.. _WSGI0115:

WSGI0115 — Unable to create socket to connect to WSGI daemon process
--------------------------------------------------------------------

:Severity: ERR
:Source: ``src/server/wsgi_remote.c``

:Logged message:
   ``Unable to create socket to connect to WSGI daemon process
   '<group>' on '<path>'.``

:Cause:
   ``apr_socket_create(AF_UNIX, SOCK_STREAM, ...)`` failed in the
   Apache child process when preparing to forward a request to the
   named WSGI daemon. Almost always file-descriptor exhaustion or
   memory pressure in the Apache child.

:Outcome:
   The current request fails with ``HTTP_INTERNAL_SERVER_ERROR``
   (500). The Apache child continues serving subsequent requests.

:Operator action:
   Check the Apache child's open-file-descriptor limit (``ulimit -n``
   for the Apache user) and overall memory pressure on the host. If
   the failure is rare and transient, no action is required.

.. _WSGI0116:

WSGI0116 — Unable to connect to WSGI daemon (listener backlog or missing socket)
--------------------------------------------------------------------------------

:Severity: ERR
:Source: ``src/server/wsgi_remote.c``

:Logged message:
   ``Unable to connect to WSGI daemon process '<group>' on
   '<path>' after multiple attempts as listener backlog limit was
   exceeded or the socket does not exist.``

:Cause:
   ``connect()`` returned ``ECONNREFUSED`` or ``EAGAIN`` repeatedly
   within the configured ``connect-timeout``. Either the daemon is
   overloaded (listener backlog full) or the daemon is not running.

:Outcome:
   The request fails with ``HTTP_SERVICE_UNAVAILABLE`` (503).

:Operator action:
   Verify the daemon group is running. If running, increase
   ``listen-backlog=`` or scale the daemon group (more processes
   or threads).

   This error can also fire as a side effect of an Apache graceful
   restart when ``WSGISocketRotation`` is left at its default of
   ``On`` and old child workers, still finishing keep-alive or
   long-running traffic, attempt to connect to a daemon socket
   path from the previous Apache generation. If the symptom recurs
   at the same time each day it is most often triggered by a
   system log-rotation service such as ``logrotate`` issuing the
   graceful restart. See
   :doc:`configuration-directives/WSGISocketRotation` for details.

.. _WSGI0117:

WSGI0117 — Unable to connect to WSGI daemon (other failure)
-----------------------------------------------------------

:Severity: ERR
:Source: ``src/server/wsgi_remote.c``

:Logged message:
   ``Unable to connect to WSGI daemon process '<group>' on
   '<path>' as user with uid=<uid>.``

:Cause:
   ``connect()`` failed with an error other than ``ECONNREFUSED``
   or ``EAGAIN`` — typically ``EACCES`` (Apache user lacks
   permission on the socket), ``ENOENT`` (path missing), or similar.

:Outcome:
   The request fails with ``HTTP_SERVICE_UNAVAILABLE`` (503).

:Operator action:
   Verify the socket file's permissions match the daemon group's
   ``user=`` and ``umask=``. Check that
   :doc:`configuration-directives/WSGISocketPrefix` is on a
   filesystem the Apache user can traverse — restrictive Apache
   runtime directories on RHEL/Fedora and similar are a common
   trigger for the EACCES variant; see
   :doc:`user-guides/configuration-issues` for the standard
   workaround.

   For ``ENOENT`` specifically, this error can also fire when an
   Apache graceful restart has rotated the daemon socket path and
   an old child worker (still finishing keep-alive or long-running
   traffic) attempts to reach a path that no longer exists. The
   trigger is most often a system log-rotation service such as
   ``logrotate`` issuing the graceful restart. See
   :doc:`configuration-directives/WSGISocketRotation` for details.

.. _WSGI0118:

WSGI0118 — Unable to proxy response to client (read timeout)
------------------------------------------------------------

:Severity: ERR
:Source: ``src/server/wsgi_remote.c``

:Logged message:
   ``Unable to proxy response to client (read timeout).``

:Cause:
   ``ap_pass_brigade`` returned ``APR_TIMEUP`` while writing
   buffered response data to the client. The client has not been
   reading data within the configured timeout.

:Outcome:
   The brigade write fails. If the client connection is aborted
   the original status code is preserved in the access log;
   otherwise ``HTTP_INTERNAL_SERVER_ERROR`` is returned.

:Operator action:
   No action for occasional cases (slow or aborting clients).
   Sustained occurrences indicate slow clients; consider
   ``request-time-limit=`` on the daemon side.

.. _WSGI0119:

WSGI0119 — Unable to proxy response from daemon to client
---------------------------------------------------------

:Severity: ERR
:Source: ``src/server/wsgi_remote.c``

:Logged message:
   ``Unable to proxy response from daemon to client.``

:Cause:
   ``ap_get_brigade`` on the input from the daemon returned a
   non-``APR_TIMEUP`` error. The daemon may have crashed or closed
   the socket prematurely.

:Outcome:
   Response is truncated; ``OK`` is returned so the access log
   records the daemon-supplied status, not 500.

:Operator action:
   Investigate daemon-side errors that would cause a premature
   socket close (look for daemon process exits or crashes).

.. _WSGI0120:

WSGI0120 — Unable to proxy response to client (write timeout)
-------------------------------------------------------------

:Severity: ERR
:Source: ``src/server/wsgi_remote.c``

:Logged message:
   ``Unable to proxy response to client (write timeout).``

:Cause:
   Same as :ref:`WSGI0118` at a different point in the response
   pipeline.

:Outcome:
   Same as :ref:`WSGI0118`.

:Operator action:
   Same as :ref:`WSGI0118`.

.. _WSGI0121:

WSGI0121 — Unable to send request details to WSGI daemon (initial)
------------------------------------------------------------------

:Severity: ERR
:Source: ``src/server/wsgi_remote.c``

:Logged message:
   ``Unable to send request details to WSGI daemon process
   '<group>' on '<path>'.``

:Cause:
   ``wsgi_send_request()`` failed to write the request envelope to
   the daemon socket. The daemon may have closed the connection.

:Outcome:
   The request fails with ``HTTP_INTERNAL_SERVER_ERROR``.

:Operator action:
   Investigate daemon health and socket buffer sizes.

.. _WSGI0122:

WSGI0122 — Unexpected status from WSGI daemon process (initial)
---------------------------------------------------------------

:Severity: ERR
:Source: ``src/server/wsgi_remote.c``

:Logged message:
   ``Unexpected status from WSGI daemon process: <N>.``

:Cause:
   The daemon's response status line was not 200 where mod_wsgi's
   restart-coordination protocol requires it. Indicates a
   protocol-level mismatch (for example an old daemon talking to a
   new mod_wsgi).

:Outcome:
   ``HTTP_INTERNAL_SERVER_ERROR``.

:Operator action:
   Restart Apache so daemon and module are versioned consistently.

.. _WSGI0123:

WSGI0123 — Unexpected status from WSGI daemon process (during restart)
----------------------------------------------------------------------

:Severity: ERR
:Source: ``src/server/wsgi_remote.c``

:Logged message:
   ``Unexpected status from WSGI daemon process: <N>.``

:Cause:
   Same as :ref:`WSGI0122`; emitted from the in-restart retry
   loop.

:Outcome:
   Same as :ref:`WSGI0122`.

:Operator action:
   Same as :ref:`WSGI0122`.

.. _WSGI0124:

WSGI0124 — Maximum number of WSGI daemon process restart attempts reached
-------------------------------------------------------------------------

:Severity: ERR
:Source: ``src/server/wsgi_remote.c``

:Logged message:
   ``Maximum number of WSGI daemon process '<group>' restart
   attempts reached: <N>.``

:Cause:
   The Apache child kept hitting ``200 Rejected`` responses
   (daemon restarting) more than the cap. The daemon group is in a
   restart loop.

:Outcome:
   The request fails with ``HTTP_SERVICE_UNAVAILABLE``.

:Operator action:
   Investigate why the daemon group is repeatedly restarting (look
   for crash, Python init failure, or ``inactivity-timeout=``).

.. _WSGI0125:

WSGI0125 — Unable to send request details to WSGI daemon (after restart)
------------------------------------------------------------------------

:Severity: ERR
:Source: ``src/server/wsgi_remote.c``

:Logged message:
   ``Unable to send request details to WSGI daemon process
   '<group>' on '<path>'.``

:Cause:
   Same as :ref:`WSGI0121` in the restart-retry loop.

:Outcome:
   Same as :ref:`WSGI0121`.

:Operator action:
   Same as :ref:`WSGI0121`.

.. _WSGI0126:

WSGI0126 — Request data read error proxying to daemon (initial)
---------------------------------------------------------------

:Severity: ERR
:Source: ``src/server/wsgi_remote.c``

:Logged message:
   ``Request data read error when proxying data to daemon
   process: <apr-error>.``

:Cause:
   ``ap_get_brigade`` for the request body failed. Typically a
   client-side disconnect during upload.

:Outcome:
   ``HTTP_REQUEST_TIME_OUT`` for ``APR_TIMEUP``, otherwise
   ``HTTP_INTERNAL_SERVER_ERROR``.

:Operator action:
   No action for occasional cases. Investigate if sustained — could
   indicate slow uploads or network issues.

.. _WSGI0127:

WSGI0127 — Request data write error proxying to daemon (closing chunk)
----------------------------------------------------------------------

:Severity: ERR
:Source: ``src/server/wsgi_remote.c``

:Logged message:
   ``Request data write error when proxying data to daemon
   process: <apr-error>.``

:Cause:
   ``wsgi_socket_send`` of the chunked-encoding terminator failed.
   The daemon may have closed the connection prematurely.

:Outcome:
   Request body proxying ends; subsequent processing decides the
   response status.

:Operator action:
   Investigate daemon health (restart or crash).

.. _WSGI0128:

WSGI0128 — Request data read error proxying to daemon (bucket read)
-------------------------------------------------------------------

:Severity: ERR
:Source: ``src/server/wsgi_remote.c``

:Logged message:
   ``Request data read error when proxying data to daemon
   process: <apr-error>.``

:Cause:
   ``apr_bucket_read`` on the request body failed. Client
   disconnect during upload is common.

:Outcome:
   The proxy loop breaks; remaining buckets are discarded.

:Operator action:
   Same as :ref:`WSGI0126`.

.. _WSGI0129:

WSGI0129 — Request data write error proxying to daemon (sendv)
--------------------------------------------------------------

:Severity: ERR
:Source: ``src/server/wsgi_remote.c``

:Logged message:
   ``Request data write error when proxying data to daemon
   process: <apr-error>.``

:Cause:
   ``wsgi_socket_sendv`` to the daemon failed. The daemon stopped
   reading.

:Outcome:
   ``child_stopped_reading`` flag set; remainder of the upload is
   discarded.

:Operator action:
   Investigate daemon health.

.. _WSGI0130:

WSGI0130 — SystemExit raised by Python atexit/sys.exitfunc
----------------------------------------------------------

:Severity: ERR
:Source: ``src/server/wsgi_shutdown.c``

:Logged message:
   ``SystemExit exception raised by Python atexit/sys.exitfunc;
   ignored.``

:Cause:
   A Python ``sys.exitfunc`` handler raised ``SystemExit`` during
   process shutdown. mod_wsgi swallows the exception so process
   shutdown continues.

:Outcome:
   Process shutdown continues; subsequent ``exitfunc`` cleanup
   runs.

:Operator action:
   Investigate the application's ``exitfunc`` handler. Compare
   :ref:`WSGI0097` which is the per-interpreter ``atexit`` variant.

.. _WSGI0131:

WSGI0131 — Exception within Python atexit/sys.exitfunc during shutdown
----------------------------------------------------------------------

:Severity: ERR
:Source: ``src/server/wsgi_shutdown.c``

:Logged message:
   ``Exception occurred within Python atexit/sys.exitfunc during
   shutdown.``

:Cause:
   The ``sys.exitfunc`` handler raised a non-``SystemExit``
   exception during process shutdown.

:Outcome:
   Process shutdown continues.

:Operator action:
   Investigate the offending ``exitfunc`` handler. Compare
   :ref:`WSGI0098`.

.. _WSGI0132:

WSGI0132 — Telemetry reporter could not open target
---------------------------------------------------

:Severity: WARNING
:Source: ``src/server/wsgi_telemetry.c``

:Logged message:
   ``Telemetry reporter could not open target '<target>'; metrics
   will not be sent.``

:Cause:
   ``wsgi_telemetry_open()`` failed. The configured telemetry
   target (a unix or UDP socket) is not reachable, or its address
   could not be parsed.

:Outcome:
   The telemetry thread does not start; metrics are not emitted.
   The daemon otherwise functions normally.

:Operator action:
   Verify the telemetry target is correct and reachable. Telemetry
   is optional observability — disabling it does not affect
   request handling.

.. _WSGI0133:

WSGI0133 — Unable to create telemetry reporter thread
-----------------------------------------------------

:Severity: WARNING
:Source: ``src/server/wsgi_telemetry.c``

:Logged message:
   ``Unable to create telemetry reporter thread; metrics will not
   be sent.``

:Cause:
   ``apr_thread_create()`` failed when starting the telemetry
   reporter.

:Outcome:
   Telemetry is disabled for the lifetime of the daemon process.

:Operator action:
   Investigate thread-limit pressure for the daemon's user.

.. _WSGI0134:

WSGI0134 — Options ExecCGI is off in this directory
---------------------------------------------------

:Severity: ERR
:Source: ``src/server/mod_wsgi.c``

:Logged message:
   ``Options ExecCGI is off in this directory.``

:Cause:
   The ``wsgi-script`` handler was matched for a request, but the
   directory's effective ``Options`` does not include ``ExecCGI``
   and the script is not reached via ``WSGIScriptAlias``. mod_wsgi
   reuses ``ExecCGI`` to gate execution of script-like content, even
   though no separate process is forked.

:Outcome:
   The request returns ``403 Forbidden``.

:Operator action:
   Add ``Options +ExecCGI`` to the relevant ``<Directory>``,
   ``<Location>``, or ``.htaccess``, or reach the script via
   ``WSGIScriptAlias`` which bypasses the check.

.. _WSGI0135:

WSGI0135 — Target WSGI script not found or unable to stat
---------------------------------------------------------

:Severity: ERR
:Source: ``src/server/mod_wsgi.c``

:Logged message:
   ``Target WSGI script not found or unable to stat.``

:Cause:
   ``r->finfo.filetype`` is zero, meaning Apache's filename mapping
   resolved to a path that ``apr_stat()`` could not classify. Either
   the file does not exist or it is not accessible to the Apache
   process.

:Outcome:
   The request returns ``404 Not Found``.

:Operator action:
   Verify the resolved filesystem path exists and is readable by the
   Apache user. The path is shown in the ``[script ...]`` log prefix.

.. _WSGI0136:

WSGI0136 — Attempt to invoke directory as WSGI application
----------------------------------------------------------

:Severity: ERR
:Source: ``src/server/mod_wsgi.c``

:Logged message:
   ``Attempt to invoke directory as WSGI application.``

:Cause:
   The resolved filename is a directory rather than a regular file.
   This usually means the URL maps to a directory by mistake — for
   example a ``WSGIScriptAlias`` target points at the parent
   directory of the script, or a ``DirectoryIndex`` rule is matching
   a directory listing.

:Outcome:
   The request returns ``403 Forbidden``.

:Operator action:
   Correct the configuration so the URL resolves to the WSGI script
   file rather than its containing directory.

.. _WSGI0137:

WSGI0137 — AcceptPathInfo off disallows user's path
---------------------------------------------------

:Severity: ERR
:Source: ``src/server/mod_wsgi.c``

:Logged message:
   ``AcceptPathInfo off disallows user's path.``

:Cause:
   The request URL contains path information after the script name,
   but ``AcceptPathInfo Off`` is configured for the location.

:Outcome:
   The request returns ``404 Not Found``.

:Operator action:
   Either remove the path-info portion of the URL, or set
   ``AcceptPathInfo On`` (or ``Default``) for the location.

.. _WSGI0138:

WSGI0138 — Unexpected value for Transfer-Encoding
-------------------------------------------------

:Severity: ERR
:Source: ``src/server/mod_wsgi.c``

:Logged message:
   ``Unexpected value for Transfer-Encoding of '<value>' supplied.
   Only 'chunked' supported.``

:Cause:
   The client supplied a ``Transfer-Encoding`` header with a value
   other than ``chunked``. mod_wsgi only supports chunked transfer
   encoding for request bodies.

:Outcome:
   The request returns ``501 Not Implemented``.

:Operator action:
   This is a client-side issue. Investigate the client if the value
   is unexpected.

.. _WSGI0139:

WSGI0139 — Chunked transfer encoding not enabled
------------------------------------------------

:Severity: ERR
:Source: ``src/server/mod_wsgi.c``

:Logged message:
   ``Request requires chunked transfer encoding, but support for
   chunked transfer encoding has not been enabled.``

:Cause:
   The client sent a request with ``Transfer-Encoding: chunked`` but
   ``WSGIChunkedRequest`` is not enabled for the location. WSGI does
   not strictly support chunked requests, so the option is off by
   default.

:Outcome:
   The request returns ``411 Length Required``.

:Operator action:
   Set ``WSGIChunkedRequest On`` for the location if the application
   is prepared to handle chunked input, or instruct the client to
   send a fixed ``Content-Length``.

.. _WSGI0140:

WSGI0140 — Unexpected Content-Length header with chunked encoding
-----------------------------------------------------------------

:Severity: ERR
:Source: ``src/server/mod_wsgi.c``

:Logged message:
   ``Unexpected Content-Length header supplied where Transfer-
   Encoding was specified as 'chunked'.``

:Cause:
   The client supplied both ``Transfer-Encoding: chunked`` and a
   ``Content-Length`` header. RFC 7230 forbids combining them.

:Outcome:
   The request returns ``400 Bad Request``.

:Operator action:
   This is a client-side protocol violation; investigate the client.

.. _WSGI0141:

WSGI0141 — Invalid Content-Length header value
----------------------------------------------

:Severity: ERR
:Source: ``src/server/mod_wsgi.c``

:Logged message:
   ``Invalid Content-Length header value of '<value>' was
   supplied.``

:Cause:
   The ``Content-Length`` header could not be parsed as a
   non-negative integer, or contained trailing garbage.

:Outcome:
   The request returns ``400 Bad Request``.

:Operator action:
   This is a client-side protocol violation; investigate the client.

.. _WSGI0142:

WSGI0142 — Embedded mode of mod_wsgi disabled at compile time
-------------------------------------------------------------

:Severity: ERR
:Source: ``src/server/mod_wsgi.c``

:Logged message:
   ``Embedded mode of mod_wsgi disabled at compile time.``

:Cause:
   A request reached the embedded-mode code path, but mod_wsgi was
   built with ``MOD_WSGI_DISABLE_EMBEDDED`` and there is no daemon
   process configured to handle it.

:Outcome:
   The request returns ``500 Internal Server Error``.

:Operator action:
   Configure a ``WSGIDaemonProcess`` and route the request to it
   via ``WSGIProcessGroup``, or rebuild mod_wsgi without the
   ``MOD_WSGI_DISABLE_EMBEDDED`` define.

.. _WSGI0143:

WSGI0143 — Embedded mode of mod_wsgi disabled by runtime configuration
----------------------------------------------------------------------

:Severity: ERR
:Source: ``src/server/mod_wsgi.c``

:Logged message:
   ``Embedded mode of mod_wsgi disabled by runtime configuration.``

:Cause:
   A request reached the embedded-mode code path, but
   ``WSGIRestrictEmbedded On`` is configured at the server level
   and there is no daemon process to handle it.

:Outcome:
   The request returns ``500 Internal Server Error``.

:Operator action:
   Configure a ``WSGIDaemonProcess`` and route the request to it
   via ``WSGIProcessGroup``, or set ``WSGIRestrictEmbedded Off``.

.. _WSGI0144:

WSGI0144 — Response header line too long from daemon process
------------------------------------------------------------

:Severity: ERR
:Source: ``src/server/wsgi_remote.c``

:Logged message:
   ``Response header line too long from daemon process '<group>'.``

:Cause:
   While reading the WSGI response from a daemon process, a single
   header line exceeded the buffer mod_wsgi uses to read response
   headers. The default buffer is 32 KiB on the request worker
   stack; it can be overridden with the ``header-buffer-size=``
   option on ``WSGIDaemonProcess`` (minimum 8192). The application
   is emitting an abnormally large header value.

:Outcome:
   The request returns ``500 Internal Server Error``. The daemon
   connection is abandoned.

:Operator action:
   Inspect the application for unusually large response headers
   (very large cookies, generated tokens, etc.) and reduce them, or
   raise ``header-buffer-size=`` on the relevant
   ``WSGIDaemonProcess`` directive to accommodate the expected
   maximum.

.. _WSGI0145:

WSGI0145 — Timeout reading response headers from daemon process
---------------------------------------------------------------

:Severity: ERR
:Source: ``src/server/wsgi_remote.c``

:Logged message:
   ``Timeout when reading response headers from daemon process
   '<group>'.``

:Cause:
   The daemon process did not return response headers within the
   configured timeout (see ``request-timeout=`` on
   ``WSGIDaemonProcess`` and the per-server ``Timeout``). The
   application is taking too long to begin producing a response.

:Outcome:
   The request returns ``504 Gateway Timeout``. The daemon
   connection is abandoned but the daemon process itself is not
   restarted.

:Operator action:
   Investigate slow application startup or blocking I/O before the
   first WSGI ``start_response``. Tune ``request-timeout=`` on the
   ``WSGIDaemonProcess`` directive if the application legitimately
   needs longer.

.. _WSGI0146:

WSGI0146 — Daemon process closed connection before sending headers
------------------------------------------------------------------

:Severity: ERR
:Source: ``src/server/wsgi_remote.c``

:Logged message:
   ``Daemon process '<group>' closed connection before sending
   complete response headers.``

:Cause:
   The daemon process closed the proxy connection mid-response
   (typically because it crashed, was killed, or restarted). See
   :doc:`user-guides/frequently-asked-questions`.

:Outcome:
   The request returns ``502 Bad Gateway``.

:Operator action:
   Inspect the daemon process logs for a Python crash, signal, or
   memory-limit kill. Check resource limits configured via
   ``WSGIDaemonProcess`` (memory, CPU).

.. _WSGI0147:

WSGI0147 — Error reading response headers from daemon process
-------------------------------------------------------------

:Severity: ERR
:Source: ``src/server/wsgi_remote.c``

:Logged message:
   ``Error reading response headers from daemon process '<group>'
   (<apr_strerror>).``

:Cause:
   An I/O error occurred while reading response headers from the
   daemon-process socket. The APR error string in parentheses gives
   the underlying cause.

:Outcome:
   The request returns ``502 Bad Gateway``.

:Operator action:
   Investigate the underlying APR error. Common causes are a
   network-stack issue on a unix-domain socket, or the daemon
   process being killed mid-response.

.. _WSGI0148:

WSGI0148 — Malformed header from daemon process
-----------------------------------------------

:Severity: ERR
:Source: ``src/server/wsgi_remote.c``

:Logged message:
   ``Malformed header '<header>' found when reading script headers
   from daemon process '<group>'.``

:Cause:
   A response-header line from the daemon did not contain a colon
   separator. The application produced a malformed header.

:Outcome:
   The request returns ``500 Internal Server Error``.

:Operator action:
   Inspect the application for code paths that emit raw header
   strings without a colon-separator (e.g. broken middleware that
   writes directly to the response).

.. _WSGI0149:

WSGI0149 — Daemon process not member of allowed groups
------------------------------------------------------

:Severity: ERR
:Source: ``src/server/wsgi_remote.c``

:Logged message:
   ``Daemon process called '<group>' cannot be accessed by this
   WSGI application as not a member of allowed groups.``

:Cause:
   The request is configured with ``WSGIProcessGroup <group>`` but
   the per-application ``WSGIRestrictProcess`` does not list
   ``<group>`` among the allowed daemon groups.

:Outcome:
   The request returns ``500 Internal Server Error``.

:Operator action:
   Add ``<group>`` to the ``WSGIRestrictProcess`` list, or change
   the ``WSGIProcessGroup`` to a permitted value.

.. _WSGI0150:

WSGI0150 — No WSGI daemon process configured (no daemon index)
--------------------------------------------------------------

:Severity: ERR
:Source: ``src/server/wsgi_remote.c``

:Logged message:
   ``No WSGI daemon process called '<group>' has been configured.``

:Cause:
   ``WSGIProcessGroup`` references a daemon group, but no
   ``WSGIDaemonProcess`` has been declared anywhere in the
   configuration.

:Outcome:
   The request returns ``500 Internal Server Error``.

:Operator action:
   Add a matching ``WSGIDaemonProcess`` directive at server or
   virtual-host scope.

.. _WSGI0151:

WSGI0151 — No WSGI daemon process configured (group lookup failed)
------------------------------------------------------------------

:Severity: ERR
:Source: ``src/server/wsgi_remote.c``

:Logged message:
   ``No WSGI daemon process called '<group>' has been configured.``

:Cause:
   ``WSGIProcessGroup`` references a daemon group name that does
   not match any declared ``WSGIDaemonProcess``.

:Outcome:
   The request returns ``500 Internal Server Error``.

:Operator action:
   Verify the spelling of the group name in ``WSGIProcessGroup``
   matches an existing ``WSGIDaemonProcess`` declaration.

.. _WSGI0152:

WSGI0152 — Daemon process not accessible from this virtual host
---------------------------------------------------------------

:Severity: ERR
:Source: ``src/server/wsgi_remote.c``

:Logged message:
   ``Daemon process called '<group>' cannot be accessed by this
   WSGI application.``

:Cause:
   The matched daemon group was declared in a different virtual
   host with a different ``ServerName``. Daemon processes are not
   shared across virtual hosts unless declared at global server
   scope.

:Outcome:
   The request returns ``500 Internal Server Error``.

:Operator action:
   Either move the ``WSGIDaemonProcess`` declaration to global
   scope, or declare a separate daemon group inside the requesting
   virtual host.

.. _WSGI0153:

WSGI0153 — Group information not available for WSGI script file
---------------------------------------------------------------

:Severity: ERR
:Source: ``src/server/wsgi_remote.c``

:Logged message:
   ``Group information not available for WSGI script file.``

:Cause:
   ``WSGIDaemonProcess script-group=`` is configured, but the
   request's ``r->finfo`` does not include valid group information
   (``APR_FINFO_GROUP``) for the WSGI script file.

:Outcome:
   The request returns ``403 Forbidden``.

:Operator action:
   Check the filesystem on which the WSGI script lives — group
   metadata may be unavailable on certain remote filesystems.

.. _WSGI0154:

WSGI0154 — Unable to determine group of WSGI script file
--------------------------------------------------------

:Severity: ERR
:Source: ``src/server/wsgi_remote.c``

:Logged message:
   ``Unable to determine group of WSGI script file from gid
   <gid>.``

:Cause:
   ``getgrgid()`` failed for the script file's group id. The gid
   has no entry in the system group database.

:Outcome:
   The request returns ``403 Forbidden``.

:Operator action:
   Ensure the script file's group id resolves to a known group, or
   change ownership of the script file.

.. _WSGI0155:

WSGI0155 — WSGI script file group does not match daemon requirement
-------------------------------------------------------------------

:Severity: ERR
:Source: ``src/server/wsgi_remote.c``

:Logged message:
   ``WSGI script file group '<group>' does not match group required
   for daemon process.``

:Cause:
   ``WSGIDaemonProcess script-group=<expected>`` is configured, but
   the script file's actual group is ``<group>``.

:Outcome:
   The request returns ``403 Forbidden``.

:Operator action:
   Either ``chgrp`` the WSGI script file to match the configured
   ``script-group=`` value, or correct the ``script-group=``
   directive.

.. _WSGI0156:

WSGI0156 — World permissions not available for WSGI script file
---------------------------------------------------------------

:Severity: ERR
:Source: ``src/server/wsgi_remote.c``

:Logged message:
   ``World permissions not available for WSGI script file.``

:Cause:
   ``r->finfo`` does not include world-permission information
   (``APR_FINFO_WPROT``) for the script file. See :ref:`WSGI0153`.

:Outcome:
   The request returns ``403 Forbidden``.

:Operator action:
   Check the filesystem hosting the script — permission metadata
   may be unavailable on certain remote filesystems.

.. _WSGI0157:

WSGI0157 — WSGI script file is writable to world (script-group)
---------------------------------------------------------------

:Severity: ERR
:Source: ``src/server/wsgi_remote.c``

:Logged message:
   ``WSGI script file is writable to world.``

:Cause:
   ``WSGIDaemonProcess script-group=`` is in effect and the script
   file has world-write permission. mod_wsgi rejects this as a
   security check — anyone with shell access to the host could
   overwrite the script.

:Outcome:
   The request returns ``403 Forbidden``.

:Operator action:
   Remove world-write permission from the WSGI script file
   (``chmod o-w``).

.. _WSGI0158:

WSGI0158 — Unable to stat parent directory of WSGI script (script-group)
------------------------------------------------------------------------

:Severity: ERR
:Source: ``src/server/wsgi_remote.c``

:Logged message:
   ``Unable to stat parent directory '<path>' of WSGI script.``

:Cause:
   ``apr_stat()`` failed on the parent directory of the WSGI script
   file when verifying ``script-group=`` constraints.

:Outcome:
   The request returns ``403 Forbidden``.

:Operator action:
   Verify the parent directory exists and is accessible to the
   Apache parent process.

.. _WSGI0159:

WSGI0159 — Unable to determine group of parent directory (script-group)
-----------------------------------------------------------------------

:Severity: ERR
:Source: ``src/server/wsgi_remote.c``

:Logged message:
   ``Unable to determine group of parent directory of WSGI script
   file from gid <gid>.``

:Cause:
   ``getgrgid()`` failed for the parent directory's group id when
   verifying ``script-group=`` constraints.

:Outcome:
   The request returns ``403 Forbidden``.

:Operator action:
   Ensure the parent directory's group id resolves to a known
   group.

.. _WSGI0160:

WSGI0160 — Parent directory group does not match daemon requirement
-------------------------------------------------------------------

:Severity: ERR
:Source: ``src/server/wsgi_remote.c``

:Logged message:
   ``Parent directory of WSGI script file has group '<group>' which
   does not match group required for daemon process.``

:Cause:
   ``WSGIDaemonProcess script-group=<expected>`` is configured, but
   the parent directory's actual group is ``<group>``.

:Outcome:
   The request returns ``403 Forbidden``.

:Operator action:
   Either ``chgrp`` the parent directory to match ``script-group=``,
   or correct the directive.

.. _WSGI0161:

WSGI0161 — Parent directory is writable to world (script-group)
---------------------------------------------------------------

:Severity: ERR
:Source: ``src/server/wsgi_remote.c``

:Logged message:
   ``Parent directory of WSGI script file is writable to world.``

:Cause:
   ``WSGIDaemonProcess script-group=`` is in effect and the parent
   directory of the script file has world-write permission, which
   would let attackers replace the script even if the file itself
   is locked down.

:Outcome:
   The request returns ``403 Forbidden``.

:Operator action:
   Remove world-write permission from the parent directory.

.. _WSGI0162:

WSGI0162 — User information not available for WSGI script file
--------------------------------------------------------------

:Severity: ERR
:Source: ``src/server/wsgi_remote.c``

:Logged message:
   ``User information not available for WSGI script file.``

:Cause:
   ``WSGIDaemonProcess script-user=`` is configured, but
   ``r->finfo`` does not include valid user information
   (``APR_FINFO_USER``) for the script file.

:Outcome:
   The request returns ``403 Forbidden``.

:Operator action:
   Check the filesystem hosting the script — owner metadata may be
   unavailable on certain remote filesystems.

.. _WSGI0163:

WSGI0163 — Unable to determine owner of WSGI script file
--------------------------------------------------------

:Severity: ERR
:Source: ``src/server/wsgi_remote.c``

:Logged message:
   ``Unable to determine owner of WSGI script file from uid
   <uid>.``

:Cause:
   ``getpwuid()`` failed for the script file's owner uid.

:Outcome:
   The request returns ``403 Forbidden``.

:Operator action:
   Ensure the script file's owner uid resolves to a known user.

.. _WSGI0164:

WSGI0164 — WSGI script file owner does not match daemon requirement
-------------------------------------------------------------------

:Severity: ERR
:Source: ``src/server/wsgi_remote.c``

:Logged message:
   ``WSGI script file owner '<user>' does not match user required
   for daemon process.``

:Cause:
   ``WSGIDaemonProcess script-user=<expected>`` is configured, but
   the script file's actual owner is ``<user>``.

:Outcome:
   The request returns ``403 Forbidden``.

:Operator action:
   Either ``chown`` the script file to match ``script-user=``, or
   correct the directive.

.. _WSGI0165:

WSGI0165 — Group permissions not available for WSGI script file
---------------------------------------------------------------

:Severity: ERR
:Source: ``src/server/wsgi_remote.c``

:Logged message:
   ``Group permissions not available for WSGI script file.``

:Cause:
   ``r->finfo`` does not include group-permission information
   (``APR_FINFO_GPROT``) for the script file under
   ``script-user=``. See :ref:`WSGI0153`.

:Outcome:
   The request returns ``403 Forbidden``.

:Operator action:
   Check the filesystem hosting the script.

.. _WSGI0166:

WSGI0166 — WSGI script file is writable to group (script-user)
--------------------------------------------------------------

:Severity: ERR
:Source: ``src/server/wsgi_remote.c``

:Logged message:
   ``WSGI script file is writable to group.``

:Cause:
   ``WSGIDaemonProcess script-user=`` is in effect and the script
   file has group-write permission, which would let any member of
   the file's group modify the script.

:Outcome:
   The request returns ``403 Forbidden``.

:Operator action:
   Remove group-write permission from the script file
   (``chmod g-w``).

.. _WSGI0167:

WSGI0167 — World permissions not available for WSGI script file (script-user)
-----------------------------------------------------------------------------

:Severity: ERR
:Source: ``src/server/wsgi_remote.c``

:Logged message:
   ``World permissions not available for WSGI script file.``

:Cause:
   ``r->finfo`` does not include world-permission information
   (``APR_FINFO_WPROT``) for the script file under
   ``script-user=``. See :ref:`WSGI0156`.

:Outcome:
   The request returns ``403 Forbidden``.

:Operator action:
   Check the filesystem hosting the script.

.. _WSGI0168:

WSGI0168 — WSGI script file is writable to world (script-user)
--------------------------------------------------------------

:Severity: ERR
:Source: ``src/server/wsgi_remote.c``

:Logged message:
   ``WSGI script file is writable to world.``

:Cause:
   ``WSGIDaemonProcess script-user=`` is in effect and the script
   file has world-write permission. See :ref:`WSGI0157`.

:Outcome:
   The request returns ``403 Forbidden``.

:Operator action:
   Remove world-write permission from the script file
   (``chmod o-w``).

.. _WSGI0169:

WSGI0169 — Unable to stat parent directory of WSGI script (script-user)
-----------------------------------------------------------------------

:Severity: ERR
:Source: ``src/server/wsgi_remote.c``

:Logged message:
   ``Unable to stat parent directory '<path>' of WSGI script.``

:Cause:
   ``apr_stat()`` failed on the parent directory of the WSGI script
   file when verifying ``script-user=`` constraints.

:Outcome:
   The request returns ``403 Forbidden``.

:Operator action:
   Verify the parent directory exists and is accessible.

.. _WSGI0170:

WSGI0170 — Unable to determine owner of parent directory (script-user)
----------------------------------------------------------------------

:Severity: ERR
:Source: ``src/server/wsgi_remote.c``

:Logged message:
   ``Unable to determine owner of parent directory of WSGI script
   file from uid <uid>.``

:Cause:
   ``getpwuid()`` failed for the parent directory's owner uid when
   verifying ``script-user=`` constraints.

:Outcome:
   The request returns ``403 Forbidden``.

:Operator action:
   Ensure the parent directory's owner uid resolves to a known
   user.

.. _WSGI0171:

WSGI0171 — Parent directory owner does not match daemon requirement
-------------------------------------------------------------------

:Severity: ERR
:Source: ``src/server/wsgi_remote.c``

:Logged message:
   ``Parent directory of WSGI script file has owner '<user>' which
   does not match user required for daemon process.``

:Cause:
   ``WSGIDaemonProcess script-user=<expected>`` is configured, but
   the parent directory's actual owner is ``<user>``.

:Outcome:
   The request returns ``403 Forbidden``.

:Operator action:
   Either ``chown`` the parent directory to match ``script-user=``,
   or correct the directive.

.. _WSGI0172:

WSGI0172 — Parent directory is writable to world (script-user)
--------------------------------------------------------------

:Severity: ERR
:Source: ``src/server/wsgi_remote.c``

:Logged message:
   ``Parent directory of WSGI script file is writable to world.``

:Cause:
   ``WSGIDaemonProcess script-user=`` is in effect and the parent
   directory of the script file has world-write permission. See
   :ref:`WSGI0161`.

:Outcome:
   The request returns ``403 Forbidden``.

:Operator action:
   Remove world-write permission from the parent directory.

.. _WSGI0173:

WSGI0173 — Parent directory is writable to group (script-user)
--------------------------------------------------------------

:Severity: ERR
:Source: ``src/server/wsgi_remote.c``

:Logged message:
   ``Parent directory of WSGI script file is writable to group.``

:Cause:
   ``WSGIDaemonProcess script-user=`` is in effect and the parent
   directory of the script file has group-write permission, which
   would let any member of the parent directory's group replace
   the script.

:Outcome:
   The request returns ``403 Forbidden``.

:Operator action:
   Remove group-write permission from the parent directory.

.. _WSGI0174:

WSGI0174 — Exception raised processing WSGI script
--------------------------------------------------

:Severity: ERR
:Source: ``src/server/wsgi_logger.c``

:Logged message:
   ``Exception (<type>) raised processing WSGI script '<filename>'
   for <interpreter-context>.`` The interpreter context is of the form
   ``main interpreter in embedded mode``, ``sub-interpreter '<name>'
   of daemon process '<group>'``, or any combination thereof. The
   header line is followed by the formatted Python traceback,
   emitted line-by-line as continuation log entries.

:Cause:
   A Python exception other than ``SystemExit`` propagated out of
   the WSGI application or one of mod_wsgi's hook scripts (auth,
   dispatch, or handler). The traceback is captured via Python's
   ``traceback.print_exception`` and written to the Apache error
   log. The exception type, value, and frames are visible in the
   continuation lines.

:Outcome:
   For request handlers the request normally returns a 500 status
   to the client (the precise behaviour depends on whether headers
   have already been sent — see related events
   :ref:`WSGI0042`-:ref:`WSGI0054` and :ref:`WSGI0086`-:ref:`WSGI0087`
   for hook-specific paths). The Apache child or daemon process
   continues running.

:Operator action:
   Investigate the Python exception in the application code. The
   continuation lines name the source file, line number, and frame
   in the failing Python code. If the failures are recurrent and
   originate inside an mod_wsgi hook (auth, dispatch), check that
   the hook script is the right version and exports the expected
   callable.

.. _WSGI0175:

WSGI0175 — SystemExit raised by WSGI script ignored
---------------------------------------------------

:Severity: ERR
:Source: ``src/server/wsgi_logger.c``

:Logged message:
   ``SystemExit (<type>) raised by WSGI script '<filename>' for
   <interpreter-context> ignored.`` Interpreter context shape as
   for :ref:`WSGI0174`. The header line is followed by the
   formatted Python traceback, emitted line-by-line as
   continuation log entries.

:Cause:
   The WSGI application or a hook script raised ``SystemExit``
   (typically via ``sys.exit()`` or an unhandled ``exit()`` call
   inside Python code). mod_wsgi traps and logs ``SystemExit``
   rather than letting it terminate the process, since the request
   thread surviving is more important than the application's
   intent to exit.

:Outcome:
   The exception is caught and logged, then cleared. The request
   handling continues as if the application had returned normally
   from the offending point — usually the request will complete
   with whatever response state had been set up before the
   ``SystemExit`` was raised, or fail with a 500 if no response
   was started.

:Operator action:
   Investigate why the application is calling ``sys.exit()``. WSGI
   applications should never use ``sys.exit()`` for normal flow
   control; this almost always indicates a configuration or
   import-time error that the application is unable to recover
   from.

.. _WSGI0176:

WSGI0176 — Basic auth provider returned empty user name string
--------------------------------------------------------------

:Severity: ERR
:Source: ``src/server/wsgi_auth.c``

:Logged message:
   ``Basic auth provider returned empty user name string.``

:Cause:
   The ``check_password(environ, user, password)`` callable in the
   ``WSGIAuthUserScript`` returned a string, which mod_wsgi treats
   as the authenticated user name to install into ``r->user``, but
   the string was empty. An empty user name would leave
   ``REMOTE_USER`` blank in the WSGI environment, omit the user
   from access log entries, and silently break any downstream
   identity-keyed logic, so mod_wsgi rejects this case rather than
   treating it as a successful authentication.

:Outcome:
   The hook returns ``AUTH_GENERAL_ERROR``; Apache responds with
   500 Internal Server Error to the client.

:Operator action:
   Fix the ``check_password`` implementation so that, on successful
   authentication, it returns either ``True`` (to confirm the
   supplied user name) or a non-empty string naming the
   authenticated user. Return ``False`` for an authentication
   failure and ``None`` when the user is not known to the script.

.. _WSGI0177:

WSGI0177 — Basic auth provider returned unexpected type
-------------------------------------------------------

:Severity: ERR
:Source: ``src/server/wsgi_auth.c``

:Logged message:
   ``Basic auth provider must return True, False, None or user
   name as string.``

:Cause:
   The ``check_password`` callable returned a value whose type is
   not one of the accepted shapes. mod_wsgi accepts ``True``
   (authentication succeeded for the supplied user name),
   ``False`` (authentication failed), ``None`` (user not known to
   the script), or a string (authentication succeeded; use this
   string as the authenticated user name). Any other return value
   is a programming error in the auth script.

:Outcome:
   The hook returns ``AUTH_GENERAL_ERROR``; Apache responds with
   500 Internal Server Error to the client.

:Operator action:
   Fix the ``check_password`` implementation to return one of the
   accepted values. Common mistakes include returning an integer,
   a tuple, or a custom object intended to carry additional data.

.. _WSGI0178:

WSGI0178 — Digest auth provider returned empty realm hash
---------------------------------------------------------

:Severity: ERR
:Source: ``src/server/wsgi_auth.c``

:Logged message:
   ``Digest auth provider returned empty realm hash.``

:Cause:
   The ``get_realm_hash(environ, user, realm)`` callable in the
   ``WSGIAuthUserScript`` returned a ``bytes`` or ``str`` value,
   which mod_wsgi treats as the precomputed
   ``MD5(user:realm:password)`` digest, but the returned value was
   empty. An empty hash would always fail Apache's digest
   comparison and produce an opaque authentication denial, so
   mod_wsgi rejects this case explicitly.

:Outcome:
   The hook returns ``AUTH_GENERAL_ERROR``; Apache responds with
   500 Internal Server Error to the client.

:Operator action:
   Fix the ``get_realm_hash`` implementation so that, when the user
   is known, it returns the non-empty hex-encoded
   ``MD5(user:realm:password)`` digest as either a ``bytes`` or
   ``str`` value. Return ``None`` to indicate that the user is not
   known to the script.

.. _WSGI0179:

WSGI0179 — Digest auth provider returned unexpected type
--------------------------------------------------------

:Severity: ERR
:Source: ``src/server/wsgi_auth.c``

:Logged message:
   ``Digest auth provider must return None or string object.``

:Cause:
   The ``get_realm_hash`` callable returned a value whose type is
   not one of the accepted shapes. mod_wsgi accepts ``None`` (user
   not known to the script) or a ``bytes``/``str`` value carrying
   the hex-encoded ``MD5(user:realm:password)`` digest. Any other
   return value is a programming error in the auth script.

:Outcome:
   The hook returns ``AUTH_GENERAL_ERROR``; Apache responds with
   500 Internal Server Error to the client.

:Operator action:
   Fix the ``get_realm_hash`` implementation to return one of the
   accepted values.

.. _WSGI0180:

WSGI0180 — Unable to register interpreter in dictionary
-------------------------------------------------------

:Severity: ERR
:Source: ``src/server/wsgi_interp.c``

:Logged message:
   ``Unable to register <interpreter-context> in interpreters
   dictionary for <process-context>.`` Interpreter context is
   ``main interpreter`` or ``sub-interpreter '<name>'``; process
   context is ``embedded mode`` or ``daemon process '<group>'``.

:Cause:
   ``PyDict_SetItemString()`` failed when ``wsgi_acquire_interpreter()``
   tried to register a freshly created sub-interpreter in mod_wsgi's
   per-process interpreters dictionary. Almost always a Python heap
   allocation failure.

:Outcome:
   The newly created sub-interpreter is decremented and discarded;
   ``wsgi_acquire_interpreter()`` returns ``NULL``. The caller
   (typically an auth or dispatch hook) returns 500 to the client.
   The next request for the same application group will retry
   creation.

:Operator action:
   Check free memory on the host. If recurrent, reduce
   ``threads=`` / ``processes=`` on heavily configured daemon
   groups.

.. _WSGI0181:

WSGI0181 — Unable to install threading._shutdown wrapper
--------------------------------------------------------

:Severity: ERR
:Source: ``src/server/wsgi_interp.c``

:Logged message:
   ``Unable to install 'threading._shutdown' wrapper for
   <interpreter-context> in <process-context>; continuing without
   atexit callback support in sub interpreters.`` Interpreter and
   process context shape as for :ref:`WSGI0180`.

:Cause:
   ``PyDict_SetItemString()`` failed when assigning the wrapper
   into the ``threading`` module dictionary during sub-interpreter
   setup. The wrapper exists because CPython does not call
   ``atexit`` handlers when a sub-interpreter is destroyed; mod_wsgi
   replaces ``threading._shutdown`` to drive them.

:Outcome:
   The interpreter is created without the wrapper installed.
   ``atexit`` handlers registered in the sub-interpreter will not
   run on its destruction. Application is otherwise functional.

:Operator action:
   Likely indicates severe memory pressure; check free memory and
   look for accompanying ``MemoryError``-class log messages. The
   process is in a degraded state.

.. _WSGI0182:

WSGI0182 — Unable to create threading._shutdown wrapper
-------------------------------------------------------

:Severity: ERR
:Source: ``src/server/wsgi_interp.c``

:Logged message:
   ``Unable to create 'threading._shutdown' wrapper for
   <interpreter-context> in <process-context>; continuing without
   atexit callback support in sub interpreters.`` Interpreter and
   process context shape as for :ref:`WSGI0180`.

:Cause:
   ``newShutdownInterpreterObject()`` returned ``NULL`` when allocating
   the wrapper object during sub-interpreter setup. Almost always a
   Python heap allocation failure.

:Outcome:
   Same as :ref:`WSGI0181`.

:Operator action:
   Same as :ref:`WSGI0181`.

.. _WSGI0183:

WSGI0183 — Unable to install signal.signal intercept
----------------------------------------------------

:Severity: ERR
:Source: ``src/server/wsgi_interp.c``

:Logged message:
   ``Unable to install 'signal.signal' intercept for
   <interpreter-context> in <process-context>; continuing without
   signal handler restrictions.`` Interpreter and process context
   shape as for :ref:`WSGI0180`.

:Cause:
   ``PyDict_SetItemString()`` failed when assigning the intercept
   into the ``signal`` module dictionary during interpreter setup.
   The intercept exists to prevent application code from registering
   signal handlers that would interfere with Apache or the daemon.

:Outcome:
   The interpreter is created without the intercept installed.
   Application code can install signal handlers via ``signal.signal()``
   that may interfere with Apache or daemon signal handling.

:Operator action:
   Likely indicates severe memory pressure; check free memory and
   look for accompanying ``MemoryError``-class log messages.

.. _WSGI0184:

WSGI0184 — Unable to create signal.signal intercept
---------------------------------------------------

:Severity: ERR
:Source: ``src/server/wsgi_interp.c``

:Logged message:
   ``Unable to create 'signal.signal' intercept for
   <interpreter-context> in <process-context>; continuing without
   signal handler restrictions.`` Interpreter and process context
   shape as for :ref:`WSGI0180`.

:Cause:
   ``newSignalInterceptObject()`` returned ``NULL`` when allocating
   the intercept object during interpreter setup. Almost always a
   Python heap allocation failure.

:Outcome:
   Same as :ref:`WSGI0183`.

:Operator action:
   Same as :ref:`WSGI0183`.

.. _WSGI0185:

WSGI0185 — Unable to replace sys.stderr with log object
-------------------------------------------------------

:Severity: ERR
:Source: ``src/server/wsgi_interp.c``

:Logged message:
   ``Unable to replace 'sys.stderr' with log object for
   <interpreter-context> in <process-context>; continuing with
   default stream object.`` Interpreter and process context shape as
   for :ref:`WSGI0180`.

:Cause:
   Either ``newLogObject()`` returned ``NULL`` or ``PySys_SetObject()``
   failed when wiring ``sys.stderr`` to a mod_wsgi log object during
   interpreter setup. Almost always a Python heap allocation failure.

:Outcome:
   The interpreter retains whatever ``sys.stderr`` object Python
   defaulted to. Output that the application writes to ``sys.stderr``
   may not reach the Apache error log.

:Operator action:
   Check free memory; the process is in a degraded state.

.. _WSGI0186:

WSGI0186 — Unable to replace sys.stdout
---------------------------------------

:Severity: ERR
:Source: ``src/server/wsgi_interp.c``

:Logged message:
   ``Unable to replace 'sys.stdout' for <interpreter-context> in
   <process-context>; continuing with default stream object.``
   Interpreter and process context shape as for :ref:`WSGI0180`.

:Cause:
   Either the constructor (``newRestrictedObject()`` when
   ``WSGIRestrictStdout On`` is in effect, otherwise ``newLogObject()``)
   returned ``NULL`` or ``PySys_SetObject()`` failed when wiring
   ``sys.stdout`` during interpreter setup.

:Outcome:
   The interpreter retains whatever ``sys.stdout`` object Python
   defaulted to. Application writes to ``sys.stdout`` may go to the
   process stdout (typically the Apache error log) rather than being
   restricted as configured.

:Operator action:
   Check free memory; the process is in a degraded state.

.. _WSGI0187:

WSGI0187 — Unable to replace sys.stdin with restricted object
-------------------------------------------------------------

:Severity: ERR
:Source: ``src/server/wsgi_interp.c``

:Logged message:
   ``Unable to replace 'sys.stdin' with restricted object for
   <interpreter-context> in <process-context>; continuing with
   default stream object.`` Interpreter and process context shape as
   for :ref:`WSGI0180`.

:Cause:
   Either ``newRestrictedObject()`` returned ``NULL`` or
   ``PySys_SetObject()`` failed when wiring ``sys.stdin`` to a
   restricted object (``WSGIRestrictStdin On``) during interpreter
   setup.

:Outcome:
   The interpreter retains whatever ``sys.stdin`` object Python
   defaulted to. Application reads from ``sys.stdin`` are not
   restricted as configured.

:Operator action:
   Check free memory; the process is in a degraded state.

.. _WSGI0188:

WSGI0188 — Exception raised during Python interpreter initialisation
--------------------------------------------------------------------

:Severity: ERR
:Source: ``src/server/wsgi_logger.c``

:Logged message:
   ``Exception (<type>) raised during Python interpreter
   initialisation for <interpreter-context>.`` Interpreter context
   is ``main interpreter in embedded mode``, ``sub-interpreter
   '<name>' of daemon process '<group>'``, or any combination.

:Cause:
   A Python exception (other than ``SystemExit``) was raised at any
   step of interpreter construction in ``newInterpreterObject()`` —
   sub-interpreter creation, optional ``mod_wsgi`` / ``apache``
   user-supplied module imports, ``WSGIPythonPath`` entry processing,
   etc. The traceback is emitted as continuation lines after this
   header. This entry usually appears between the :ref:`WSGI0035`
   header and the consequence message (:ref:`WSGI0038` /
   :ref:`WSGI0103`).

:Outcome:
   Interpreter setup is aborted; the partially constructed
   interpreter is destroyed. The caller propagates failure to its
   own caller via the consequence message.

:Operator action:
   Read the traceback to identify the underlying cause. If a user
   has supplied a ``mod_wsgi.py`` or ``apache.py`` on the Python
   search path that raises during import, fix or remove it.

.. _WSGI0189:

WSGI0189 — SystemExit raised during Python interpreter initialisation
---------------------------------------------------------------------

:Severity: ERR
:Source: ``src/server/wsgi_logger.c``

:Logged message:
   ``SystemExit (<type>) raised during Python interpreter
   initialisation for <interpreter-context>; ignored.`` Interpreter
   context shape as for :ref:`WSGI0188`.

:Cause:
   A ``SystemExit`` exception was raised at some step of interpreter
   construction. mod_wsgi swallows it rather than letting it
   terminate the process.

:Outcome:
   Same as :ref:`WSGI0188`. The interpreter is destroyed and the
   caller propagates failure.

:Operator action:
   Investigate any user code (typically a user-supplied ``mod_wsgi.py``
   or import-time side effect of a ``WSGIPythonPath`` entry) that
   may be calling ``sys.exit()`` or raising ``SystemExit`` during
   import.
