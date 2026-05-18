==========================
Logging from Applications
==========================

This page covers how output from Python application code reaches the
Apache error log under mod_wsgi: ``print()``, the file-like objects
``sys.stdout``, ``sys.stderr`` and ``wsgi.errors``, the standard
library ``logging`` module, and the ``warnings`` module. The mechanics
of where output goes, how it is decorated, when it is flushed, and
which Apache directives shape the result are all in scope.

For diagnostic tools and lifecycle messages produced by mod_wsgi
itself, see :doc:`debugging-techniques`.

Concrete worked examples live in the source tree as
``tests/print.wsgi``, ``tests/logging.wsgi`` and
``tests/warnings.wsgi``. The log excerpts in this page are taken from
those files.

How output reaches the Apache error log
---------------------------------------

mod_wsgi routes every Python text stream that an application can write
to into the Apache error log. The routing mechanism is per-write,
not per-scope: at process startup mod_wsgi installs replacement
stream objects in ``sys.stdout`` and ``sys.stderr`` that stay in
place for the lifetime of the interpreter. On every write to either
stream, the replacement consults the calling thread's state to
decide which of two Apache logging entry points the write is
forwarded through:

* If the calling thread is currently handling a request, the write
  is routed through the same per-request error stream that
  ``environ['wsgi.errors']`` exposes for that request, ultimately
  calling ``ap_log_rerror`` with the request's remote-client and
  matched-script decoration. A direct write to
  ``environ['wsgi.errors']`` takes the same path.
* If the calling thread is not handling a request, the write is
  routed to ``ap_log_error`` with no request decoration. This is
  the path taken during module-import time, during background-thread
  work the application launched, and during interpreter shutdown.

Two consequences follow from the per-thread routing:

* Concurrent requests in the same daemon process each get their own
  request decoration on log records, because the lookup happens
  per-write and reflects the thread that issued the write. Two
  request handlers running side by side cannot accidentally have
  each other's log lines tagged with the wrong request.
* Background threads an application or imported library started at
  module-import time run independently of any request. Their writes
  via ``sys.stdout`` / ``sys.stderr`` land in the Apache error log
  via ``ap_log_error`` without request decoration, regardless of
  which request happens to be in flight when they write. That
  matches the threads' actual lifetime: they have nothing to do
  with the particular request running alongside them.
  ``environ['wsgi.errors']`` is not a usable substitute for a
  long-lived thread; it is invalidated when the request that
  supplied it returns, and using a stale reference from a
  background thread that outlives the request raises.

Output written to any of these streams is buffered by line and
emitted as Apache log records via ``ap_log_error`` (at module scope
or from background threads) or ``ap_log_rerror`` (during a request,
when called from the request's handler thread). For application
output routed through these streams the log level on the Apache
side is fixed at ``error``: every line lands as ``[wsgi:error]``,
regardless of what the application code intended.

The consequence is that Apache's ``LogLevel`` directive does *not*
filter stream-routed application output. ``LogLevel wsgi:warn``
only gates mod_wsgi's own diagnostic messages (process lifecycle,
request escalation events, internal errors); output emitted from
the application via ``print()``, ``sys.stdout`` / ``sys.stderr``,
or ``environ['wsgi.errors']`` reaches the log regardless. Filtering
of that output happens entirely on the Python side, via
``logging.Logger.setLevel``, handler-level filters, or the
``warnings`` filter chain.

For applications that want Apache's ``LogLevel`` to act as a real
filter on Python output, mod_wsgi ships ``mod_wsgi.LogHandler``: a
``logging.Handler`` subclass that bypasses the stream alias and
calls Apache's logging API directly with the matching ``APLOG_*``
level. Records emitted via the handler land at ``[wsgi:debug]``,
``[wsgi:info]``, ``[wsgi:warn]``, ``[wsgi:error]`` or ``[wsgi:crit]``
in the Apache log, so ``LogLevel wsgi:LEVEL`` filters them
operator-side. See `Routing via mod_wsgi.LogHandler`_ below.

Module-scope versus request-scope decoration
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The non-application content around each log line breaks down into
two layers. The outer wrap (timestamp, module:level tag, process and
thread id, remote client when applicable) is produced by Apache from
its ``ErrorLogFormat`` directive; operators who have customised that
directive will see different decoration. The ``[script ...]`` tag
visible in request-scope lines is added by mod_wsgi itself, embedded
into the message body before Apache logs it, so it is present
whatever ``ErrorLogFormat`` is set to.

A line emitted at module-import time under Apache's default
``ErrorLogFormat`` looks like:

.. code-block:: text

    [Mon May 18 09:42:49.323831 2026] [wsgi:error] [pid 5875:tid 8474794176] DEBUG wsgi-app module-scope logger.debug

A line emitted from inside a request handler picks up additional
context:

.. code-block:: text

    [Mon May 18 09:42:52.672416 2026] [wsgi:error] [pid 5875:tid 6129135616] [remote ::1:59739] [script /var/tmp/mod_wsgi-localhost:8000:501/htdocs/] DEBUG wsgi-app request logger.debug

The ``[script ...]`` tag identifies the WSGI script the work was
routed to. The absence of both ``[script ...]`` and the
client-identifying part of the Apache wrap is the visual signal that
the record was emitted outside any active request: typically at
module-import time, in a service-script daemon, in a background
thread, or after the request that triggered the work has already
returned.

Output via print()
------------------

Bare ``print()`` writes to ``sys.stdout``. mod_wsgi's replacement
``sys.stdout`` and ``sys.stderr`` (described above) decide their
routing per-write based on whether the calling thread is handling a
request. When a request handler calls any of these forms, all four
land on the same decorated log line, because they all resolve to the
same per-request target:

.. code-block:: python

    print('hello')                            # via sys.stdout
    print('hello', file=sys.stdout)           # same stream
    print('hello', file=sys.stderr)           # same stream
    print('hello', file=environ['wsgi.errors'])

At module-import time only the first three forms are available.
``environ['wsgi.errors']`` is a per-request key that does not exist
outside an active request, so module-scope code that wants to emit
output must use ``sys.stdout`` or ``sys.stderr``. mod_wsgi's
replacement streams route writes from module-import code through
``ap_log_error``, so a module-scope ``print()`` still reaches the
log; it just lands without the ``[remote ...]`` and ``[script ...]``
decoration that a request-scope emission picks up.

A trailing newline is interpreted by the stream as a line terminator:
the buffered fragment is flushed to Apache, and Apache emits it as
one error-log record. A ``print()`` call with ``end=''`` writes a
fragment without a newline; the fragment is held in the buffer until
one of four things happens:

1. A subsequent write to the same stream contains a newline. The
   newline terminates the buffered fragment and the combined content
   is emitted as one log record.
2. The application calls ``flush()`` on the stream. The buffered
   fragment is emitted immediately as a log record, even without an
   embedded newline.
3. The request completes. mod_wsgi flushes any partial line still
   buffered on the per-request stream.
4. The interpreter shuts down. Module-scope partial lines that were
   never flushed surface here.

Each of these triggers produces a properly terminated log record:
Apache's logging machinery appends a newline if the buffered content
did not contain one, so a ``flush()`` against an unterminated
fragment still emits a well-formed line.

Module-scope partial lines are easy to miss. Module init code that
does ``print('progress: ', end='')`` and expects the next module's
init to continue on the same line will buffer the fragment until
something else flushes the stream, which under mod_wsgi may not
happen until process shutdown. Terminate module-scope prints with a
newline, or call ``flush()`` explicitly.

CGI portability
~~~~~~~~~~~~~~~

The four destinations are not equally portable. An application that
needs to remain usable under a CGI-to-WSGI bridge should restrict
its log output to ``sys.stderr`` and ``environ['wsgi.errors']``,
and read its request body only from ``environ['wsgi.input']``. The
CGI contract reserves standard output for the HTTP response body
and standard input for the request body, so any
``sys.stdout``-bound write or ``sys.stdin`` read by application
code under CGI corrupts the response or consumes the request body.

mod_wsgi does not enforce this restriction by default: writes to
``sys.stdout`` from an application reach the Apache error log the
same way ``sys.stderr`` writes do, and reads from ``sys.stdin``
return end-of-stream rather than failing. The
:doc:`../configuration-directives/WSGIRestrictStdout` and
:doc:`../configuration-directives/WSGIRestrictStdin` directives
can be set to ``On`` to make access to those streams raise an
exception, so a portability violation surfaces as a runtime error
rather than slipping through unnoticed.

CGI-to-WSGI bridging is essentially obsolete in modern
deployments, so this is rarely a practical constraint. The
restriction directives remain useful for applications that aim to
support both hosting models, and for catching accidental
``sys.stdout`` writes during development.

Multi-line strings split into multiple log records
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A single write that contains embedded newlines splits into one
Apache record per newline-delimited segment. A traceback string
produced by ``traceback.format_exc()``, a warning message produced
by ``warnings.formatwarning()``, or any other multi-line string sees
its full Apache decoration repeated on every segment:

.. code-block:: text

    [...] [script ...] Traceback (most recent call last):
    [...] [script ...]   File "/path/to/app.py", line 42, in handler
    [...] [script ...]     raise RuntimeError('bang')
    [...] [script ...] RuntimeError: bang

A log aggregator that builds one event per Apache record will see
four separate events for this single exception. The traceback is
readable in a ``tail -f`` view but verbose in a structured store.

The 8K per-record cap
~~~~~~~~~~~~~~~~~~~~~

Apache's log machinery, and mod_wsgi's stream buffering, share an
8 KiB per-record cap. Content longer than the cap is silently
truncated. Multi-line emission gives each segment its own 8 KiB
budget, so a deep traceback with twenty short frames still surfaces
intact: each frame fits in one record.

Collapsing a multi-line message into one record (for example by
replacing newlines with a separator character) puts the entire
content inside a single 8 KiB budget, minus Apache's decoration. The
risk is that the *end* of the truncated record is what gets dropped,
and the end of a Python traceback is where the actual exception type
and message live. If a structured log target needs one record per
event, JSON-encoded log lines (with literal ``\n`` escapes inside a
message field) are a safer pattern than a separator-character
collapse, because the consumer can validate that the JSON parsed
intact.

The Python logging module
-------------------------

The ``logging`` module is the recommended path for application
output. It supports level-based filtering, structured formatters, and
multiple handlers, none of which the raw ``print()`` route offers.

Configure logging at module-import time, before any request runs:

.. code-block:: python

    import logging

    logging.basicConfig(
        level=logging.DEBUG,
        format='%(levelname)s %(name)s %(message)s',
    )

    logger = logging.getLogger(__name__)

The format string deliberately omits ``%(asctime)s``. Apache
decorates every error-log record with its own timestamp, so a
``%(asctime)s`` in the Python format produces double-timestamped
lines. Including the Python log level (``%(levelname)s``) and the
logger name (``%(name)s``) is useful, because Apache itself classifies
every record as ``[wsgi:error]`` regardless of the Python level: the
Python level distinction lives only in the message body.

A typical request-scope log line then looks like:

.. code-block:: text

    [...] [script ...] INFO myapp request received

with ``INFO myapp`` carrying the Python-side metadata and the
``[wsgi:error]`` tag carrying the Apache-side classification.

Python-side filtering with the default handler
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

With the default ``StreamHandler`` that ``basicConfig`` installs,
Apache's ``LogLevel`` does not gate Python output (every record
lands at ``[wsgi:error]`` after the stream alias). A noisy
application logger has to be quietened on the Python side:

.. code-block:: python

    logging.getLogger('chatty-library').setLevel(logging.WARNING)

This suppresses ``DEBUG`` and ``INFO`` from the named logger before
the record reaches the handler chain, while the root logger
continues to emit all five levels for everything else. Python-side
filtering remains useful when routing through
``mod_wsgi.LogHandler`` (as a per-application floor below the
Apache-side ceiling, see `Routing via mod_wsgi.LogHandler`_), but
it is the only filter mechanism available to the default handler
path.

Routing via mod_wsgi.LogHandler
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

``mod_wsgi.LogHandler`` is a ``logging.Handler`` subclass shipped
with mod_wsgi that routes records through Apache's logging API
directly, preserving the Python log level. Where the default
``StreamHandler`` writes to ``sys.stderr`` (and so lands at
``[wsgi:error]`` after the stream alias), ``LogHandler`` calls
``ap_log_*error`` with the matching ``APLOG_*`` level so each
record lands at the corresponding Apache level tag:

==================== ====================
Python level         Apache level tag
==================== ====================
``CRITICAL``         ``[wsgi:crit]``
``ERROR``            ``[wsgi:error]``
``WARNING``          ``[wsgi:warn]``
``INFO``             ``[wsgi:info]``
``DEBUG``            ``[wsgi:debug]``
==================== ====================

Non-standard Python levels (custom levels, ``NOTSET``) round down
to the next-lower Apache level.

Configure once at module-import time:

.. code-block:: python

    import logging
    import mod_wsgi

    logging.basicConfig(
        level=logging.DEBUG,
        handlers=[mod_wsgi.LogHandler()],
        format='%(name)s %(message)s',
    )

The format string drops ``%(levelname)s`` because Apache now
classifies every record at the matching level, so the level is
already visible in the ``[wsgi:LEVEL]`` tag that prefixes the
line.

Apache's ``LogLevel`` directive filters these records the same way
it filters mod_wsgi's own diagnostic messages: ``LogLevel
wsgi:warn`` drops application ``DEBUG`` and ``INFO`` records
before the formatter even runs. The operator-side level acts as a
*ceiling*: records the application emitted at lower levels still
get written, and records above the ceiling are dropped at the
Apache boundary. Python-side ``setLevel`` and filters remain the
*floor*, deciding what gets produced at all in the first place.

Per record the handler consults the calling thread's state to
pick between ``ap_log_rerror`` (request-handling thread) and
``ap_log_error`` (module-init, background thread, shutdown), so
the request-decoration story matches the stream-routed path:
module-scope and background-thread records land without
``[remote ...]`` / ``[script ...]`` decoration; request-scope
records pick it up.

``record.pathname`` and ``record.lineno`` are passed through to
Apache as the source location, so an operator with ``%F`` in
``ErrorLogFormat`` sees the application's ``logger.*`` call site
rather than the emit-site inside mod_wsgi.

When mixing ``mod_wsgi.LogHandler`` with the default
``basicConfig``-installed ``StreamHandler`` (for instance to route
some loggers via Apache and others via the default path), set
``propagate = False`` on the LogHandler-attached loggers so their
records do not also bubble up to root and surface twice (once at
the proper Apache level via ``LogHandler``, once at
``[wsgi:error]`` via the inherited ``StreamHandler``).

``mod_wsgi.LogHandler`` and ``logging.captureWarnings(True)`` are
independent. Configuring both is the natural setup when
application output *and* ``warnings.warn(...)`` output should
share the same Apache-level-aware path.

The logger.exception() path
~~~~~~~~~~~~~~~~~~~~~~~~~~~

``logger.exception('summary')`` (called inside an ``except:`` block)
emits the summary message at ``ERROR`` level followed by the
formatted traceback. The traceback is a multi-line string; each line
becomes its own Apache log record, with the request decoration
repeated on every line as described in
`Multi-line strings split into multiple log records`_.

The lastResort fallback
~~~~~~~~~~~~~~~~~~~~~~~

If no handler is configured anywhere on a logger's path to root, and
the logger has no propagation route to root, Python falls back to
its ``logging.lastResort`` handler. ``lastResort`` is a
``StreamHandler`` at level ``WARNING`` writing to ``sys.stderr``
with no formatter beyond ``%(message)s``. Under mod_wsgi the line
still reaches Apache's error log via the ``sys.stderr`` alias, but
without the level prefix or logger name that an explicit
configuration would supply:

.. code-block:: text

    [...] [script ...] this is the message body, no level, no name

``DEBUG`` and ``INFO`` from such a logger are silently dropped.
``logger.exception()`` still works but loses the ``ERROR``
classification. The practical rule: always call ``basicConfig``, or
attach an explicit handler, at module-import time. Relying on
``lastResort`` is rarely what an application wants.

The warnings module
-------------------

Python's ``warnings`` module is a parallel diagnostic stream
alongside the ``logging`` module. Libraries emit
``DeprecationWarning``, ``PendingDeprecationWarning``, and others via
``warnings.warn(...)``. By default these go to ``sys.stderr`` via
``warnings.showwarning()``, which under mod_wsgi means they reach
the Apache error log via the same alias used for ``print()`` output.

Two independent layers shape what happens to a warning:

* The **filter chain** decides whether the warning fires at all. If
  a matching filter says ``ignore``, no record is produced; if it
  says ``error``, the warning is converted into a raised exception.
* If the warning fires, the **routing** layer decides where the
  emitted record goes. By default it goes to ``sys.stderr`` via
  ``warnings.showwarning``; a call to ``logging.captureWarnings(True)``
  redirects fired warnings through a logger named ``py.warnings``
  instead.

The two layers are independent. ``WSGIPythonWarnings ignore::FutureWarning``
suppresses ``FutureWarning`` even when ``captureWarnings(True)`` is
active: the warning never fires, so there is nothing to route.
Conversely, ``captureWarnings(True)`` only changes the destination
of warnings that survive the filter chain.

Operator-level filter control: WSGIPythonWarnings
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The :doc:`../configuration-directives/WSGIPythonWarnings` directive
populates Python's warnings filter chain at interpreter startup.
Each occurrence appends one entry, using the standard ``-W`` syntax
(``action:message:category:module:lineno``):

.. code-block:: apache

    # Convert every warning into an exception, surfacing
    # deprecations as a request-time failure rather than a log line.
    WSGIPythonWarnings error

    # Or, suppress just one noisy category from a specific package.
    WSGIPythonWarnings ignore::DeprecationWarning:somepackage.legacy

The directive is the operator-level equivalent of the ``-W``
command-line flag or the ``PYTHONWARNINGS`` environment variable.
It only applies at interpreter startup; application code that calls
``warnings.simplefilter(...)`` or ``warnings.filterwarnings(...)``
at module load time can modify or replace the chain after the fact.

mod_wsgi-express exposes a matching ``--python-warnings`` option:

.. code-block:: bash

    mod_wsgi-express start-server app.wsgi --python-warnings error

A repeated ``--python-warnings`` emits multiple ``WSGIPythonWarnings``
directives, matching the directive's append semantics.

Application-level filter control
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Two ``warnings`` module functions interact differently with whatever
``WSGIPythonWarnings`` installed:

``warnings.simplefilter(action)``
    Replaces the entire filter chain with a single ``action`` entry.
    Any entries from ``WSGIPythonWarnings`` are wiped. Use only when
    the application genuinely wants to override the operator-level
    policy.

``warnings.filterwarnings(action, ...)``
    Prepends one entry to the chain. Operator-level entries from
    ``WSGIPythonWarnings`` remain in place; the new entry takes
    precedence only for warnings it matches. This is the cooperative
    option for application code that wants its own policy without
    overriding the operator.

For applications that need to add an entry without disturbing
operator configuration, prefer ``filterwarnings``.

Routing warnings into the logging system
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

``logging.captureWarnings(True)`` redirects fired warnings through a
logger named ``py.warnings`` at level ``WARNING``. After the call,
``warnings.warn()`` records pick up the same format and handler
chain as ordinary application logging. The redirection is reversible
via ``logging.captureWarnings(False)`` if a specific code path
genuinely wants the original ``sys.stderr`` route.

Pair ``captureWarnings(True)`` with a configured ``logging``
handler:

.. code-block:: python

    import logging

    logging.basicConfig(
        level=logging.DEBUG,
        format='%(levelname)s %(name)s %(message)s',
    )
    logging.captureWarnings(True)

A fired warning then appears under the same format as ordinary
logging output, prefixed by ``WARNING py.warnings``. The body is a
multi-line string produced by ``warnings.formatwarning()``: a
header line carrying the file, line number, category and message,
and an indented source-line repeat. Each line surfaces as its own
Apache log record, as described in
`Multi-line strings split into multiple log records`_.

One subtlety: the ``StreamHandler`` that ``captureWarnings`` routes
through adds its own newline terminator on top of the newline
already present at the end of ``formatwarning``'s output. The result
is that fired warnings under ``captureWarnings(True)`` produce one
extra empty record per warning. This is cosmetic; the warning
content itself is intact.

Time zones in multi-interpreter processes
-----------------------------------------

A single mod_wsgi daemon process can host more than one Python
sub-interpreter, each running a different application
(:doc:`embedded-and-daemon-mode`). The ``TZ`` environment variable
is *not* per-interpreter state: it is read by the system C library
during the next call to ``localtime`` (or via ``time.tzset()``) and
applies to the whole process.

If one application changes ``os.environ['TZ']`` and calls
``time.tzset()``, the next ``time.localtime()`` call from a
different application in the same process picks up the new value.
For application logging that means a format including
``%(asctime)s`` can produce timestamps in a time zone the
application did not configure, depending on the order in which the
interpreters ran their initialisation.

Two practical responses:

* Omit ``%(asctime)s`` from application logging formats. Apache
  decorates every error-log record with its own timestamp anyway,
  generated from a process-level configuration that does not depend
  on Python interpreter state.
* If a per-application timestamp is genuinely required (because
  the application is writing to its own log file via a separate
  handler, for instance), prefer ``logging.Formatter`` with
  ``datefmt=`` plus explicit conversion through
  ``datetime.now(tz=zoneinfo.ZoneInfo(...))`` rather than relying
  on the C-library ``TZ`` value.

Single-interpreter deployments are not exposed to this hazard, but
single-interpreter is not the default for processes hosting
multiple ``WSGIScriptAlias`` mounts.

Recommended baseline configuration
----------------------------------

A starting point that combines the recommendations above:

.. code-block:: python

    import logging
    import mod_wsgi

    # Route logging records through Apache's error log at the
    # matching Apache level, so LogLevel wsgi:LEVEL becomes a real
    # filter on application output. Apache supplies the timestamp
    # and the [wsgi:LEVEL] tag; the Python format carries only the
    # logger name and the message body.
    logging.basicConfig(
        level=logging.DEBUG,
        handlers=[mod_wsgi.LogHandler()],
        format='%(name)s %(message)s',
    )

    # Route warnings.warn() output through the same logging chain
    # so library warnings pick up the same format and Apache-level
    # treatment as application logging.
    logging.captureWarnings(True)

    logger = logging.getLogger(__name__)

Pair the above with an operator-level
``WSGIPythonWarnings error::DeprecationWarning`` (or the
``mod_wsgi-express --python-warnings error::DeprecationWarning``
form) during CI runs to surface deprecation regressions as failed
requests rather than silent log lines.

For per-library filtering once the application has imports under
control, use named-logger ``setLevel`` calls (Python logging) or
``filterwarnings`` calls (warnings module), preserving operator
defaults rather than replacing them.

See also
--------

* :doc:`../configuration-directives/WSGIPythonWarnings` for the
  directive that controls the Python warnings filter chain.
* :doc:`mod-wsgi-express-quickstart` for the matching
  ``--python-warnings`` option in the express wrapper.
* :doc:`../configuration-directives/WSGIRestrictStdout` and
  :doc:`../configuration-directives/WSGIRestrictStdin` for
  enforcing CGI-portable use of the standard streams.
* :doc:`debugging-techniques` for diagnostic messages produced by
  mod_wsgi itself, distinct from application output.
* :doc:`embedded-and-daemon-mode` for the multi-interpreter
  process model that the time-zone caveat above refers to.
* :doc:`external-telemetry-service` for the structured-metrics
  pipeline, an alternative to log-line scraping for observability.
