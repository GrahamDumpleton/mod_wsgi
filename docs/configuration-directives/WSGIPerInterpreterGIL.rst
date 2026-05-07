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
