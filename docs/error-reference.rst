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
