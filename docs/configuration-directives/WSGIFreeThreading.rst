=================
WSGIFreeThreading
=================

:Description: Enable free-threaded Python (GIL disabled) for the matched process.
:Syntax: ``WSGIFreeThreading On|Off``
:Default: ``WSGIFreeThreading Off``
:Context: server config

Controls whether the Python interpreter in the matched process is
started with the GIL disabled, as introduced by PEP 703 in Python
3.13. Free-threading is a process-wide setting fixed at interpreter
initialisation time; it cannot be scoped to a single sub interpreter.

mod_wsgi forces the GIL on by default even on a free-threaded Python
build. Free-threading is opt-in per process via this directive.

For background on the three GIL modes mod_wsgi supports and worked
examples mixing them across processes, see
:doc:`../user-guides/gil-modes-and-free-threading`.

To enable free-threading for every process where mod_wsgi initialises
Python (the embedded interpreter and every daemon process group), set
the directive at server config scope::

  WSGIFreeThreading On

To enable it only for selected processes, place it inside a
:doc:`WSGIInterpreterOptions` container with a ``process-group=``
selector. A nested setting overrides the top-level default for the
matching process only.

Selectors
---------

Permitted scoping for ``WSGIFreeThreading``:

* Top-level (no container): matches every process.
* ``<WSGIInterpreterOptions>`` with no selectors: matches every
  process. Same effect as a top-level setting.
* ``<WSGIInterpreterOptions process-group=%{GLOBAL}>``: matches the
  embedded interpreter only. Daemon processes are unaffected.
* ``<WSGIInterpreterOptions process-group=NAME>``: matches the named
  daemon process group only.

The directive is **not** valid in a container that has
``application-group=`` set. Free-threading is a process-wide setting
and cannot be scoped per application group. If the directive appears
in such a container a warning is logged at config load and the
directive is ignored for that container; see :ref:`WSGI0201`.

Python version requirements
---------------------------

Free-threading requires Python 3.13 or later, configured at build
time with ``--disable-gil``. mod_wsgi must be built against that
Python interpreter (the C macro ``Py_GIL_DISABLED`` must be defined).

If ``WSGIFreeThreading On`` is set on a Python build that does not
support free-threading, a warning is logged at config load and the
directive has no effect; see :ref:`WSGI0200`.

Default behaviour on free-threaded builds
-----------------------------------------

A free-threaded Python build will, by default, leave the choice of
whether to enable the GIL to extension declarations: the GIL stays
off if every loaded extension declares
``Py_mod_gil = Py_MOD_GIL_NOT_USED``, otherwise CPython re-enables
the GIL at extension import time and emits a runtime warning.

mod_wsgi overrides this by setting ``PyConfig.enable_gil`` explicitly
on free-threaded builds, defaulting to ``_PyConfig_GIL_ENABLE``
(GIL on) for every process. This trades CPython's automatic
"decide based on extensions" behaviour for predictable startup. To
opt a process into free-threading, set ``WSGIFreeThreading On`` for
that process; mod_wsgi then sets ``enable_gil`` to
``_PyConfig_GIL_DISABLE``.

C extension compatibility
-------------------------

A Python C extension imported by an interpreter running with the GIL
disabled should declare its support for the no-GIL build with a
``Py_mod_gil = Py_MOD_GIL_NOT_USED`` slot in its multi-phase init
table. Extensions that do not declare the slot are imported anyway
under the explicit ``_PyConfig_GIL_DISABLE`` mod_wsgi sets, but
CPython logs a runtime warning per extension to flag that they have
not been audited for the no-GIL runtime.

This is the most common first-time issue when enabling
``WSGIFreeThreading``: extensions that work fine under the GIL log
warnings (or behave incorrectly) under the no-GIL runtime. Pure
Python modules and extensions that have been audited for free-
threading are unaffected.

Interaction with WSGIPerInterpreterGIL
--------------------------------------

:doc:`WSGIPerInterpreterGIL` controls per-sub-interpreter GIL (PEP
684) within a process that has a GIL. It is meaningful only when
``WSGIFreeThreading`` is **not** active for the same process. When
both apply to the same process, free-threading wins:
``WSGIPerInterpreterGIL`` is a no-op and a warning is logged at sub
interpreter creation time; see :ref:`WSGI0202`.

The two directives can therefore be mixed across different processes
in the same Apache server. For example, on a free-threaded Python
build:

* The embedded interpreter can run free-threaded while one daemon
  process group runs with the GIL enabled and selected sub
  interpreters in that daemon process get their own GIL.
* Or one daemon process group can run free-threaded while another
  runs with the GIL enabled and selected sub interpreters get their
  own GIL.

Interaction with WSGISwitchInterval
-----------------------------------

The :doc:`WSGISwitchInterval` directive (and the ``switch-interval=``
parameter on :doc:`WSGIDaemonProcess`) controls how often the GIL is
yielded. With no GIL there is nothing to yield, so both are no-ops
when ``WSGIFreeThreading`` is active for the process. mod_wsgi
warns and skips the ``sys.setswitchinterval()`` call; see
:ref:`WSGI0203`, :ref:`WSGI0204` and :ref:`WSGI0205`.
