=====================
WSGIPerInterpreterGIL
=====================

:Description: Enable per-interpreter GIL for Python sub interpreters.
:Syntax: ``WSGIPerInterpreterGIL On|Off``
:Default: ``WSGIPerInterpreterGIL Off``
:Context: server config

Controls whether Python sub interpreters created by mod_wsgi are given
their own GIL, as introduced by PEP 684 in Python 3.12. When set to
``On``, each sub interpreter runs with its own independent GIL rather
than sharing the process-wide GIL with every other interpreter.

For background on the three GIL modes mod_wsgi supports and worked
examples mixing them across processes, see
:doc:`../user-guides/gil-modes-and-free-threading`.

To enable per-interpreter GIL process-wide, set the directive at server
config scope::

  WSGIPerInterpreterGIL On

To enable it only for selected interpreters, place it inside a
:doc:`WSGIInterpreterOptions` container with ``process-group=`` and/or
``application-group=`` selectors. A nested setting overrides the
top-level default for the matching interpreters only.

The main Python interpreter always uses the original process-wide GIL
and cannot be given its own. A ``WSGIPerInterpreterGIL On`` setting
that resolves to the main interpreter (for example a container with
``application-group=%{GLOBAL}``) is silently ignored for that
interpreter.

When a sub interpreter is created with its own GIL, mod_wsgi notes
that fact in the Apache error log entry that records the interpreter's
creation.

Python version requirements
---------------------------

Per-interpreter GIL requires Python 3.12 or later. On older Python
versions the directive is accepted but logs a configuration-time
warning and has no effect; sub interpreters continue to share the
process-wide GIL.

A free-threaded Python build (PEP 703) does not by itself prevent the
directive from working. mod_wsgi defaults to running with the GIL
enabled even on free-threaded builds, so per-interpreter GIL applies
normally unless free-threading has been opted in for the process via
:doc:`WSGIFreeThreading`. When free-threading is active in the
process, ``WSGIPerInterpreterGIL`` is a per-interpreter no-op (there
is no GIL to allocate per interpreter); a warning is logged at sub
interpreter creation time.

C extension compatibility
-------------------------

A Python C extension imported by an interpreter that has its own GIL
must declare its support for multiple per-interpreter GILs. Modules
using PEP 489 multi-phase initialisation declare this with a
``Py_mod_multiple_interpreters`` slot whose value is
``Py_MOD_PER_INTERPRETER_GIL_SUPPORTED``. Modules that do not declare
support, or that explicitly declare ``Py_MOD_MULTIPLE_INTERPRETERS_NOT_SUPPORTED``,
will fail to import in an own-GIL sub interpreter.

This is the most common first-time failure mode when enabling the
directive: extensions that work fine under the shared GIL refuse to
import once their interpreter has its own. Pure Python modules and
extensions that have been audited for sub-interpreter safety are
unaffected.

When per-interpreter GIL is enabled for an interpreter, that
interpreter's switch interval can be set independently of other
interpreters in the same process via :doc:`WSGISwitchInterval` placed
inside a matching :doc:`WSGIInterpreterOptions` container. Under the
shared GIL the switch interval is process-global and cannot meaningfully
differ between interpreters.

Experimenting with sub-interpreter load balancing
-------------------------------------------------

Per-interpreter GIL is a recent CPython feature and how to
make best use of it in a WSGI hosting context is still
being explored. The recipe below sketches one way to
experiment: route incoming requests across a fixed set of
named sub-interpreters in a single daemon process, each
holding its own GIL, so CPU-bound work can proceed in
parallel within one process.

Three pieces compose:

* ``WSGIPerInterpreterGIL On`` enables the per-interpreter
  GIL for sub interpreters mod_wsgi creates.
* A :doc:`WSGIDispatchScript` picks an application group
  name per request (the sub-interpreter to route into).
* ``WSGIApplicationGroup %{ENV:APPLICATION_GROUP}`` (or
  the ``application-group=`` option on ``WSGIScriptAlias``)
  tells mod_wsgi to read the application group from the
  environment variable the dispatch script populates.

A simple round-robin dispatch script that spreads requests
across four named sub-interpreters::

    # /etc/apache2/wsgi/dispatch.py

    import itertools
    import threading

    _lock = threading.Lock()
    _counter = itertools.count()

    INTERPRETERS = ['interp_0', 'interp_1', 'interp_2', 'interp_3']

    def application_group(environ):
        with _lock:
            n = next(_counter)
        return INTERPRETERS[n % len(INTERPRETERS)]

The matching Apache configuration runs the application in
a single daemon process with enough threads to drive all
sub-interpreters concurrently::

    WSGIPerInterpreterGIL On

    WSGIDispatchScript /etc/apache2/wsgi/dispatch.py

    WSGIDaemonProcess myapp processes=1 threads=15
    WSGIScriptAlias / /srv/myapp/wsgi.py \
        process-group=myapp \
        application-group=%{ENV:APPLICATION_GROUP}

Under ``mod_wsgi-express`` the equivalent combines
``--application-group`` for the env-var expansion with
``--include-file`` for the directives express does not
have first-class options for. With ``per-interp-gil.conf``
containing::

    WSGIPerInterpreterGIL On
    WSGIDispatchScript /tmp/dispatch.py

the express invocation is::

    mod_wsgi-express start-server wsgi.py \
        --processes 1 --threads 15 \
        --application-group %{ENV:APPLICATION_GROUP} \
        --include-file /tmp/per-interp-gil.conf

Caveats:

* ``processes=1`` is deliberate. Multiple daemon
  processes would each have their own copies of the
  sub-interpreter set, so the dispatch script would
  distribute requests across distinct address spaces
  rather than across parallel sub-interpreters in one
  process. Whether a multi-process shape is the right
  one is a separate experiment.
* Each Apache child runs its own copy of the dispatch
  script and so has its own round-robin counter; the
  global distribution across all Apache children is
  approximately round-robin but not strictly. A
  hash-based dispatch (``hash(client_ip) % N``) is
  globally deterministic at the cost of uneven
  distribution under skewed traffic.
* Every Python C extension imported into a sub
  interpreter must declare PEP 489 multiple-interpreter
  support, as covered in `C extension compatibility`_.
  Failure modes when an extension does not support it
  surface at import time, before traffic flows.
