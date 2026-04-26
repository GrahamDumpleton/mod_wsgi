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
    but still-running subsystem. (Currently not assigned error codes.)

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
   ``Python initialisation failed; Python based handlers will not be
   available in this child process.``

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
   ``Python child initialisation failed; Python based handlers will not
   be available in this child process.``

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
   ``Unable to change root directory to '<root>'.``

:Cause:
   ``chroot()`` failed during daemon-process startup when the
   ``WSGIDaemonProcess`` directive specified a ``root=`` chroot target.
   Typical underlying causes are: the daemon process is not running with
   sufficient privilege to call ``chroot``, the chroot directory does
   not exist, or the path is not a directory.

:Outcome:
   The daemon process exits. Apache will respawn it; the same failure
   will recur until the underlying cause is fixed.

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
   ``Unable to set group id to gid=<gid>.``

:Cause:
   ``setgid()`` failed during daemon-process startup when applying the
   group specified by ``WSGIDaemonProcess group=...``. The most common
   cause is that the daemon process is not running with sufficient
   privilege to change group; this should not happen on a normal Apache
   install where the parent runs as root.

:Outcome:
   The daemon process exits. Apache respawns it.

:Operator action:
   Verify the group exists and that Apache is running with sufficient
   privilege to change group identity at fork time.

.. _WSGI0005:

WSGI0005 — Unable to set supplementary groups for daemon process
----------------------------------------------------------------

:Severity: ALERT
:Source: ``src/server/wsgi_daemon.c``

:Logged message:
   ``Unable to set supplementary groups for uname=<user> of '<groups>'.``

:Cause:
   ``setgroups()`` failed when applying the supplementary group list
   given via ``WSGIDaemonProcess supplementary-groups=...``. Either one
   of the named groups does not exist, the list contains an invalid
   identifier, or the process lacks privilege to set supplementary
   groups.

:Outcome:
   The daemon process exits. Apache respawns it.

:Operator action:
   Confirm every group named in the directive exists. Verify Apache has
   privilege to manage supplementary groups at fork time.

.. _WSGI0006:

WSGI0006 — Unable to initialise default groups for daemon process
-----------------------------------------------------------------

:Severity: ALERT
:Source: ``src/server/wsgi_daemon.c``

:Logged message:
   ``Unable to set groups for uname=<user> and gid=<gid>.``

:Cause:
   ``initgroups()`` failed while loading the supplementary-group list
   for the daemon's user from the system group database. Most often the
   user does not exist in the system database at the time the daemon
   process starts (NSS/LDAP unavailable, user removed, etc.).

:Outcome:
   The daemon process exits. Apache respawns it.

:Operator action:
   Verify the user named on ``WSGIDaemonProcess user=...`` resolves
   correctly in the system group database (``id <user>``).

.. _WSGI0007:

WSGI0007 — Unable to change to user id for daemon process
---------------------------------------------------------

:Severity: ALERT
:Source: ``src/server/wsgi_daemon.c``

:Logged message:
   ``Unable to change to uid=<uid>.``

:Cause:
   ``setuid()`` failed during daemon-process startup. On Linux this is
   most often caused by the target user reaching their per-user process
   limit (``RLIMIT_NPROC``); ``setuid()`` returns ``EAGAIN`` in that
   case. Other causes are insufficient privilege to change identity at
   all.

:Outcome:
   The daemon process logs this and a follow-up :ref:`WSGI0008` message,
   sleeps 20 seconds (anti-fork-bomb guard), and exits. Apache respawns
   it; the same failure will recur until the cause is fixed.

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
   ``Failure to configure the daemon process correctly and process left
   in unspecified state. Restarting daemon process after delay.``

:Cause:
   Companion log message to :ref:`WSGI0007`. Emitted immediately after
   a ``setuid`` failure to make explicit that the daemon was unable to
   drop privileges and is therefore exiting rather than continuing in a
   potentially elevated state.

:Outcome:
   The daemon process sleeps 20 seconds and exits. Apache respawns it.

:Operator action:
   See :ref:`WSGI0007`.

.. _WSGI0009:

WSGI0009 — Unable to change working directory for daemon process
----------------------------------------------------------------

:Severity: ALERT
:Source: ``src/server/wsgi_daemon.c``

:Logged message:
   ``Unable to change working directory to '<path>'.``

:Cause:
   ``chdir()`` failed when applying the directory specified by
   ``WSGIDaemonProcess home=...``. Most often the directory does not
   exist, is not a directory, or is unreadable to the daemon user.

:Outcome:
   The daemon process exits. Apache respawns it.

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
   uid=<uid>.``

:Cause:
   No explicit ``home=`` was given on ``WSGIDaemonProcess`` and the
   daemon attempted to fall back to the home directory of the user it
   is running as. ``chdir()`` to that home directory failed — usually
   because the home directory does not exist or is unreadable.

:Outcome:
   The daemon process exits. Apache respawns it.

:Operator action:
   Either give an explicit ``home=`` value on ``WSGIDaemonProcess``, or
   ensure the user's home directory exists and is accessible.

.. _WSGI0011:

WSGI0011 — Unable to determine home directory for daemon process user
---------------------------------------------------------------------

:Severity: ALERT
:Source: ``src/server/wsgi_daemon.c``

:Logged message:
   ``Unable to determine home directory for uid=<uid>.``

:Cause:
   No explicit ``home=`` was given on ``WSGIDaemonProcess`` and the
   ``getpwuid()`` lookup for the daemon user's home directory failed.
   Usually the user is not present in the system password database at
   the time the daemon starts (NSS/LDAP unavailable, user removed).

:Outcome:
   The daemon process exits. Apache respawns it.

:Operator action:
   Verify the user resolves correctly (``getent passwd <uid>``), or set
   an explicit ``home=`` on ``WSGIDaemonProcess`` so no lookup is
   required.

.. _WSGI0012:

WSGI0012 — Couldn't create UNIX domain socket for daemon process
----------------------------------------------------------------

:Severity: ALERT
:Source: ``src/server/wsgi_daemon.c``

:Logged message:
   ``Couldn't create unix domain socket.``

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

WSGI0013 — Couldn't bind UNIX domain socket for daemon process
--------------------------------------------------------------

:Severity: ALERT
:Source: ``src/server/wsgi_daemon.c``

:Logged message:
   ``Couldn't bind unix domain socket '<path>'.``

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

WSGI0014 — Couldn't listen on UNIX domain socket for daemon process
-------------------------------------------------------------------

:Severity: ALERT
:Source: ``src/server/wsgi_daemon.c``

:Logged message:
   ``Couldn't listen on unix domain socket.``

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

WSGI0015 — Couldn't change owner of UNIX domain socket for daemon process
-------------------------------------------------------------------------

:Severity: ALERT
:Source: ``src/server/wsgi_daemon.c``

:Logged message:
   ``Couldn't change owner of unix domain socket '<path>' to uid=<uid>.``

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
   ``Wait on thread <id> wakeup condition variable failed.``

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

WSGI0017 — Couldn't acquire accept mutex; daemon shutting down
--------------------------------------------------------------

:Severity: CRIT
:Source: ``src/server/wsgi_daemon.c``

:Logged message:
   ``Couldn't acquire accept mutex '<path>'. Shutting down daemon
   process.``

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
   ``Unable to poll daemon socket for '<path>'. Shutting down daemon
   process.``

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

WSGI0019 — Couldn't release accept mutex
----------------------------------------

:Severity: CRIT
:Source: ``src/server/wsgi_daemon.c``

:Logged message:
   ``Couldn't release accept mutex '<path>'.``

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

WSGI0020 — Couldn't create worker thread condition variable
-----------------------------------------------------------

:Severity: ALERT
:Source: ``src/server/wsgi_daemon.c``

:Logged message:
   ``Couldn't create worker thread <i> state condition variable in
   daemon process '<group>'.``

:Cause:
   ``apr_thread_cond_create()`` failed when initialising a worker
   thread's wakeup condition variable during daemon startup. Almost
   always a memory or thread-resource exhaustion.

:Outcome:
   The daemon sends ``SIGTERM`` to its own pid and exits. Apache
   respawns it.

:Operator action:
   Check memory and thread limits on the host. Reduce the
   ``threads=`` value on ``WSGIDaemonProcess`` if the daemon is
   configured for an unusually high number of workers.

.. _WSGI0021:

WSGI0021 — Couldn't create worker thread state mutex
----------------------------------------------------

:Severity: ALERT
:Source: ``src/server/wsgi_daemon.c``

:Logged message:
   ``Couldn't create worker thread <i> state mutex variable in daemon
   process '<group>'.``

:Cause:
   ``apr_thread_mutex_create()`` failed when initialising a worker
   thread's state mutex during daemon startup. Almost always a
   memory or thread-resource exhaustion.

:Outcome:
   The daemon sends ``SIGTERM`` to its own pid and exits. Apache
   respawns it.

:Operator action:
   See :ref:`WSGI0020`.

.. _WSGI0022:

WSGI0022 — Couldn't create worker thread
----------------------------------------

:Severity: ALERT
:Source: ``src/server/wsgi_daemon.c``

:Logged message:
   ``Couldn't create worker thread <i> in daemon process '<group>'.``

:Cause:
   ``apr_thread_create()`` failed when starting a worker thread
   during daemon startup. Usually thread-resource exhaustion at the
   process or system level.

:Outcome:
   The daemon sends ``SIGTERM`` to its own pid and exits. Apache
   respawns it.

:Operator action:
   Check thread limits (``ulimit -u``, ``/proc/sys/kernel/threads-max``)
   and reduce ``threads=`` on the daemon group if appropriate.

.. _WSGI0023:

WSGI0023 — Failed read on signal pipe
-------------------------------------

:Severity: ALERT
:Source: ``src/server/wsgi_daemon.c``

:Logged message:
   ``Failed read on signal pipe '<group>'.``

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

WSGI0024 — Couldn't spawn daemon process
----------------------------------------

:Severity: ALERT
:Source: ``src/server/wsgi_daemon.c``

:Logged message:
   ``Couldn't spawn process '<group>'.``

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
   ``Failure to configure the daemon process correctly and process
   left in unspecified state. Restarting daemon process after delay.``

:Cause:
   ``wsgi_setup_access()`` returned an error during daemon startup.
   The actual cause will have been logged immediately above as one of
   :ref:`WSGI0003` through :ref:`WSGI0011`. This message is the
   companion log explaining that the daemon is exiting because it
   could not safely complete privilege-drop / chroot / chdir setup.

:Outcome:
   The daemon process sleeps 20 seconds (anti-fork-bomb) and exits.
   Apache respawns it.

:Operator action:
   See whichever of :ref:`WSGI0003` to :ref:`WSGI0011` was logged
   immediately before this entry.

.. _WSGI0026:

WSGI0026 — Couldn't initialise accept mutex in daemon process
-------------------------------------------------------------

:Severity: CRIT
:Source: ``src/server/wsgi_daemon.c``

:Logged message:
   ``Couldn't initialise accept mutex in daemon process '<path>'.``

:Cause:
   ``apr_proc_mutex_child_init()`` failed when re-attaching the
   shared accept mutex in a freshly forked daemon process. Most
   often the mutex file or sysvsem segment is missing or
   inaccessible to the daemon user after privilege drop.

:Outcome:
   The daemon process sleeps 20 seconds and exits. Apache respawns
   it.

:Operator action:
   Verify ``WSGISocketPrefix`` points at a directory that is
   accessible to the daemon user. If using sysvsem locks, check
   that ``ipcs -s`` shows the expected semaphores and that they
   were not removed externally.

.. _WSGI0027:

WSGI0027 — Couldn't initialise signal pipe in daemon process
------------------------------------------------------------

:Severity: ALERT
:Source: ``src/server/wsgi_daemon.c``

:Logged message:
   ``Couldn't initialise signal pipe in daemon process '<group>'.``

:Cause:
   ``apr_file_pipe_create()`` failed when the daemon was setting up
   its internal signal pipe used to receive shutdown notifications.
   Almost always a file-descriptor or memory exhaustion.

:Outcome:
   The daemon process sleeps 20 seconds (anti-fork-bomb) and exits.
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
   ``Python initialisation failed in daemon process '<group>'.``

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
   ``Python child initialisation failed; Python based handlers will
   not be available in this daemon process.``

:Cause:
   Same as :ref:`WSGI0002` but in a daemon-mode process.
   ``wsgi_python_child_init()`` failed inside the daemon.

:Outcome:
   The daemon process continues running but cannot serve Python
   requests for the rest of its lifetime.

:Operator action:
   See :ref:`WSGI0002`.

.. _WSGI0030:

WSGI0030 — Couldn't create accept lock for daemon group
-------------------------------------------------------

:Severity: CRIT
:Source: ``src/server/wsgi_daemon.c``

:Logged message:
   ``Couldn't create accept lock '<path>' (<mechanism>).``

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

WSGI0031 — Couldn't set permissions on sysvsem accept mutex
-----------------------------------------------------------

:Severity: CRIT
:Source: ``src/server/wsgi_daemon.c``

:Logged message:
   ``Couldn't set permissions on accept mutex '<path>' (sysvsem).``

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

WSGI0032 — Couldn't set permissions on flock accept mutex
---------------------------------------------------------

:Severity: CRIT
:Source: ``src/server/wsgi_daemon.c``

:Logged message:
   ``Couldn't set permissions on accept mutex '<path>' (flock).``

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
   ``Request origin could not be validated.``

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
   ``Request origin could not be validated.``

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

WSGI0035 — Failed to create Python sub-interpreter
--------------------------------------------------

:Severity: CRIT
:Source: ``src/server/wsgi_interp.c``

:Logged message:
   ``Failed to create interpreter '<name>'.``

:Cause:
   ``newInterpreterObject()`` failed during construction of a Python
   sub-interpreter for an application group. Almost always a memory
   exhaustion or a Python ``Py_NewInterpreter()`` failure. The
   partially constructed sub-interpreter is cleaned up before this
   message is logged.

:Outcome:
   The caller receives ``NULL`` and treats the application group as
   unavailable. Subsequent attempts to acquire the same group will
   re-attempt creation.

:Operator action:
   Check free memory and the Python build for compatibility. If
   recurrent, raise the Apache ``LogLevel`` for the ``wsgi`` module
   to ``debug`` to capture additional context, and check whether
   third-party Python C extensions are misbehaving in
   sub-interpreters.

.. _WSGI0036:

WSGI0036 — Python interpreter configuration failed
--------------------------------------------------

:Severity: CRIT
:Source: ``src/server/wsgi_interp.c``

:Logged message:
   ``Initializing Python failed: <message>``

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
   ``Unable to initialise Python types for this child process.``

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

WSGI0038 — Unable to create main Python interpreter wrapper
-----------------------------------------------------------

:Severity: CRIT
:Source: ``src/server/wsgi_interp.c``

:Logged message:
   ``Unable to create wrapper object for main Python interpreter in
   this child process.``

:Cause:
   ``newInterpreterObject(NULL)`` failed when creating the cached
   wrapper for the main Python interpreter at child / daemon startup.
   Almost always a memory exhaustion at the moment of allocation.

:Outcome:
   ``wsgi_python_initialized`` is set to 0 and the function returns
   ``APR_EGENERAL``. The child or daemon process cannot serve Python
   requests.

:Operator action:
   Check free memory on the host. Reduce ``threads=`` or
   ``processes=`` on heavily configured daemon groups if the system
   is at memory pressure during Apache startup.

.. _WSGI0039:

WSGI0039 — Unable to register main Python interpreter wrapper
-------------------------------------------------------------

:Severity: CRIT
:Source: ``src/server/wsgi_interp.c``

:Logged message:
   ``Unable to record wrapper for main Python interpreter in
   interpreters dictionary for this child process.``

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

WSGI0040 — Cannot acquire interpreter during daemon startup script preload
--------------------------------------------------------------------------

:Severity: CRIT
:Source: ``src/server/wsgi_interp.c``

:Logged message:
   ``Cannot acquire interpreter '<name>'.``

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
