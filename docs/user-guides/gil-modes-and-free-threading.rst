============================
GIL Modes and Free-Threading
============================

This guide covers the three Python GIL configurations
mod_wsgi can drive: the classic process-wide shared GIL,
PEP 684 per-interpreter GIL (Python 3.12+), and PEP 703
free-threading (Python 3.13+). It describes what
mod_wsgi exposes for each, how the modes interact, how
to mix them across embedded mode and daemon process
groups in one Apache server, and how to wire them up
under ``mod_wsgi-express`` (which does not have
first-class command line options for any of the
relevant directives).

For directive-level reference see
:doc:`../configuration-directives/WSGIFreeThreading`,
:doc:`../configuration-directives/WSGIPerInterpreterGIL`,
and :doc:`../configuration-directives/WSGIInterpreterOptions`.
The :doc:`processes-and-threading` and
:doc:`embedded-and-daemon-mode` guides cover the
underlying process and sub interpreter model that this
page builds on. Read those first if "MPM" or "sub
interpreter" is unfamiliar.

The three GIL modes
===================

mod_wsgi runs Python interpreters inside Apache child
processes (embedded mode) and inside daemon processes
(daemon mode). Each such process loads CPython into its
address space and creates one main interpreter plus one
or more sub interpreters for the WSGI applications it
hosts. The GIL configuration is a property of the
*process*, not of the request, the application, or the
Apache vhost.

Shared GIL (default)
--------------------

Every Python interpreter in the process, the main
interpreter and every sub interpreter, shares a single
process-wide GIL. Only one Python frame runs at a time
per process. Concurrency across requests comes from
running multiple processes (Apache child processes or
``WSGIDaemonProcess`` daemon processes), each with its
own independent GIL.

This is the historical CPython model and the default
mod_wsgi configuration on every supported Python
version.

Per-interpreter GIL (PEP 684, Python 3.12+)
-------------------------------------------

The process keeps its process-wide GIL for the main
interpreter, and sub interpreters can be configured
individually to run with their own independent GIL.
Sub interpreters with their own GIL can run Python
frames in parallel within a single process, on
different OS threads.

Enabled with :doc:`../configuration-directives/WSGIPerInterpreterGIL`.
The setting can be made process-wide or scoped to
specific sub interpreters via
:doc:`../configuration-directives/WSGIInterpreterOptions`
containers with ``process-group=`` and / or
``application-group=`` selectors. The main interpreter
always uses the process-wide GIL; a setting that
resolves to the main interpreter is silently ignored
for that interpreter.

A C extension imported by a sub interpreter that has
its own GIL must declare PEP 489 multi-interpreter
support via ``Py_mod_multiple_interpreters`` set to
``Py_MOD_PER_INTERPRETER_GIL_SUPPORTED``. Extensions
that do not, or that explicitly declare
``Py_MOD_MULTIPLE_INTERPRETERS_NOT_SUPPORTED``, fail to
import in such a sub interpreter.

Free-threading (PEP 703, Python 3.13+)
--------------------------------------

The entire process runs with the GIL disabled. Every
interpreter, main and sub, executes without any GIL.
Every OS thread in the process can execute Python code
in parallel, up to the number of available cores.

Free-threading requires a Python build configured with
``--disable-gil`` (commonly distributed as
``python3.13t``, ``python3.14t``, and so on). It is a
*process-wide* setting fixed at
``Py_InitializeFromConfig`` time, so unlike
per-interpreter GIL it cannot be scoped per sub
interpreter.

Enabled with
:doc:`../configuration-directives/WSGIFreeThreading`.
The setting can be applied at server config scope (every
mod_wsgi-managed process) or to individual processes
via ``<WSGIInterpreterOptions process-group=...>``.
Scoping on ``application-group=`` is not valid: a
process either runs free-threaded or it does not.

A C extension imported into a free-threaded interpreter
should declare ``Py_mod_gil = Py_MOD_GIL_NOT_USED`` in
its multi-phase init slots. Extensions without the
declaration are still imported, but CPython logs a
runtime warning per extension to flag that they have
not been audited for the no-GIL runtime.

What mod_wsgi provides
======================

Three directives plus one container:

:doc:`../configuration-directives/WSGIFreeThreading`
    Process-wide opt-in to free-threading. mod_wsgi
    forces the GIL on by default even on free-threaded
    Python builds; this directive disables it for the
    matched process.

:doc:`../configuration-directives/WSGIPerInterpreterGIL`
    Per-sub-interpreter opt-in to per-interpreter GIL.
    Sub interpreters within the directive's scope are
    created with their own GIL.

:doc:`../configuration-directives/WSGIInterpreterOptions`
    Container that scopes both of the above (and a few
    related per-interpreter directives) to a subset of
    interpreters by ``process-group=`` and / or
    ``application-group=``. Top-level settings serve as
    defaults; container settings override per match,
    with the most-specific match winning.

:doc:`../configuration-directives/WSGISwitchInterval`
    Calls ``sys.setswitchinterval()`` to tune how often
    the GIL is yielded. Has no effect when
    free-threading is active in the process. Can be
    placed inside ``<WSGIInterpreterOptions>`` to vary
    the value per sub interpreter, but only for sub
    interpreters that also have their own GIL (under
    the shared GIL the switch interval is a
    process-global value).

Selectors
---------

The two selectors map onto mod_wsgi's existing process
and application group concepts:

``process-group=NAME``
    Matches the embedded interpreter (when set to the
    empty string or ``%{GLOBAL}``) or a specific named
    ``WSGIDaemonProcess`` group.

``application-group=NAME``
    Matches a resolved application group name.
    ``%{ENV:VAR}`` expansion is supported; the match is
    re-evaluated per request in that case.

Omitting a selector matches every value of that
dimension. The empty container
``<WSGIInterpreterOptions>`` matches every interpreter.

Precedence and constraints
--------------------------

Free-threading wins. If both directives resolve to the
same process and ``WSGIFreeThreading`` is on,
``WSGIPerInterpreterGIL`` is a no-op (there is no GIL
to allocate per interpreter); a warning is logged at
sub interpreter creation time (see :ref:`WSGI0202`).

``WSGIFreeThreading`` is not valid in a container that
sets ``application-group=``. The directive in such a
container is ignored with a warning at config load (see
:ref:`WSGI0201`).

``WSGIPerInterpreterGIL`` resolving to the main
interpreter (via ``application-group=%{GLOBAL}``) is
silently ignored: the main interpreter cannot be given
its own GIL.

``WSGIPerInterpreterGIL On`` on a Python older than
3.12, or ``WSGIFreeThreading On`` on a Python build not
configured with ``--disable-gil``, are accepted at
configuration parse time but log a warning and have no
effect (see :ref:`WSGI0198` and :ref:`WSGI0200`).

Mixing modes across processes
=============================

Because the GIL configuration is per-process, different
Apache child and daemon processes in the same server
can each run in a different mode. The
``process-group=`` selector is the mechanism for
expressing that.

The examples below assume mod_wsgi has been built
against a free-threaded Python build (for instance
``python3.14t``). On a non-free-threaded build the
``WSGIFreeThreading`` directive is still accepted but
has no effect.

Single mode, everywhere
-----------------------

Classic shared GIL in every process, the historical
default::

    LoadModule wsgi_module modules/mod_wsgi.so
    WSGIDaemonProcess myapp processes=4 threads=15
    WSGIScriptAlias / /srv/myapp/wsgi.py \
        process-group=myapp

Same shape with free-threading active in every
mod_wsgi-managed process (embedded interpreter and
every daemon group)::

    LoadModule wsgi_module modules/mod_wsgi.so
    WSGIFreeThreading On
    WSGIDaemonProcess myapp processes=4 threads=15
    WSGIScriptAlias / /srv/myapp/wsgi.py \
        process-group=myapp

Same shape with per-interpreter GIL active for every
sub interpreter mod_wsgi creates::

    LoadModule wsgi_module modules/mod_wsgi.so
    WSGIPerInterpreterGIL On
    WSGIDaemonProcess myapp processes=4 threads=15
    WSGIScriptAlias / /srv/myapp/wsgi.py \
        process-group=myapp

Free-threading for one daemon group only
----------------------------------------

A single daemon group runs free-threaded; the embedded
interpreter and any other daemon groups stay on the
shared GIL::

    LoadModule wsgi_module modules/mod_wsgi.so

    WSGIDaemonProcess freethreaded processes=1 threads=30
    WSGIDaemonProcess legacy       processes=4 threads=15

    <WSGIInterpreterOptions process-group=freethreaded>
        WSGIFreeThreading On
    </WSGIInterpreterOptions>

    WSGIScriptAlias /modern /srv/modern/wsgi.py \
        process-group=freethreaded
    WSGIScriptAlias /legacy /srv/legacy/wsgi.py \
        process-group=legacy

Useful while a free-threading-safe new application is
deployed alongside a classic codebase whose C
extensions have not been audited for the no-GIL
runtime.

Free-threading for embedded mode only
-------------------------------------

The ``process-group=%{GLOBAL}`` selector targets the
embedded interpreter::

    <WSGIInterpreterOptions process-group=%{GLOBAL}>
        WSGIFreeThreading On
    </WSGIInterpreterOptions>

Mainly useful for auth and dispatch scripts that
benefit from intra-process parallelism. The WSGI
application itself, if served from a daemon group, is
unaffected.

Per-interpreter GIL for one daemon group
----------------------------------------

A single daemon process runs multiple sub interpreters,
each holding its own GIL, while a second daemon group
runs unchanged on the shared GIL::

    LoadModule wsgi_module modules/mod_wsgi.so

    WSGIDaemonProcess parallel processes=1 threads=15
    WSGIDaemonProcess simple   processes=4 threads=15

    <WSGIInterpreterOptions process-group=parallel>
        WSGIPerInterpreterGIL On
    </WSGIInterpreterOptions>

    WSGIDispatchScript /etc/apache2/wsgi/dispatch.py
    WSGIScriptAlias /api /srv/api/wsgi.py \
        process-group=parallel \
        application-group=%{ENV:APPLICATION_GROUP}
    WSGIScriptAlias /www /srv/www/wsgi.py \
        process-group=simple

For the dispatch-script side of the recipe (routing
requests across a fixed set of named sub interpreters)
see the worked example in
:doc:`../configuration-directives/WSGIPerInterpreterGIL`.

Mixed: free-threaded and per-interpreter GIL groups
---------------------------------------------------

The two modes can coexist in the same server, in
different daemon groups. The directive resolver picks
the right configuration per process::

    LoadModule wsgi_module modules/mod_wsgi.so

    WSGIDaemonProcess freethreaded processes=1 threads=30
    WSGIDaemonProcess parallel     processes=1 threads=15
    WSGIDaemonProcess simple       processes=2 threads=15

    <WSGIInterpreterOptions process-group=freethreaded>
        WSGIFreeThreading On
    </WSGIInterpreterOptions>

    <WSGIInterpreterOptions process-group=parallel>
        WSGIPerInterpreterGIL On
    </WSGIInterpreterOptions>

    WSGIScriptAlias /modern /srv/modern/wsgi.py \
        process-group=freethreaded
    WSGIScriptAlias /api    /srv/api/wsgi.py \
        process-group=parallel \
        application-group=%{ENV:APPLICATION_GROUP}
    WSGIScriptAlias /www    /srv/www/wsgi.py \
        process-group=simple

A separate daemon process group for each mode is the
natural unit of separation because the GIL setting is
per-process. Combining free-threading and
per-interpreter GIL in the same process is not a
supported configuration; see the precedence rules
above.

Per-interpreter GIL for one application group only
--------------------------------------------------

Inside a single daemon process, only one application
group runs with its own GIL; other application groups
in the same process keep the shared GIL::

    WSGIDaemonProcess mixed processes=1 threads=15

    <WSGIInterpreterOptions process-group=mixed
                            application-group=cpu_app>
        WSGIPerInterpreterGIL On
    </WSGIInterpreterOptions>

    WSGIScriptAlias /cpu /srv/cpu/wsgi.py \
        process-group=mixed \
        application-group=cpu_app
    WSGIScriptAlias /io  /srv/io/wsgi.py \
        process-group=mixed \
        application-group=io_app

The same approach works with a dispatch script:
``application-group=%{ENV:APPLICATION_GROUP}`` resolves
per request, and the container match is evaluated then.

Per-interpreter switch interval
-------------------------------

When a sub interpreter has its own GIL, its switch
interval can be tuned independently of the rest of the
process::

    <WSGIInterpreterOptions process-group=parallel
                            application-group=cpu_app>
        WSGIPerInterpreterGIL On
        WSGISwitchInterval 0.002
    </WSGIInterpreterOptions>

Setting ``WSGISwitchInterval`` inside an
``application-group=`` container without per-interpreter
GIL on the same match is rejected: under the shared
GIL the switch interval is a process-global value, so
a per-application setting would silently affect every
interpreter in the process. See
:doc:`../configuration-directives/WSGIInterpreterOptions`
for the validation rules.

C extension compatibility
=========================

The two opt-in modes have different compatibility
requirements, with different failure modes when an
extension does not meet them. The shared-GIL default
also has a long-standing sub-interpreter constraint
that is covered separately and summarised first.

Shared GIL: sub-interpreter constraint
--------------------------------------

C extensions that use the simplified
``PyGILState_Ensure`` / ``PyGILState_Release`` API
assume a single interpreter per process and do not
work correctly outside the main interpreter. NumPy,
SciPy and modules built on top of them are the
prominent examples. WSGI applications that import
such extensions have to run in the main interpreter,
which under mod_wsgi means setting
``WSGIApplicationGroup %{GLOBAL}`` (or, in daemon
mode, relying on the daemon process's own main
interpreter). The trade-offs and failure modes are
described under "WSGIApplicationGroup and C extension
modules" in :doc:`configuration-issues` and "Multiple
Python Sub Interpreters" in
:doc:`application-issues`. This constraint applies
under the shared GIL irrespective of the two opt-in
modes below.

Per-interpreter GIL: hard import failure
----------------------------------------

A sub interpreter with its own GIL refuses to import a
C extension that has not declared PEP 489
multi-interpreter support. The error surfaces at
import time, before traffic flows. Typical declaration
in a C extension's multi-phase init table::

    static PyModuleDef_Slot module_slots[] = {
        {Py_mod_exec, exec_module},
        {Py_mod_multiple_interpreters,
            Py_MOD_PER_INTERPRETER_GIL_SUPPORTED},
        {0, NULL}
    };

An extension that declares
``Py_MOD_MULTIPLE_INTERPRETERS_NOT_SUPPORTED``, or
omits the slot entirely, fails to import inside any
sub interpreter with its own GIL. The application
group then fails to load and requests routed to it
return 500.

Free-threading: runtime warning, then load anyway
-------------------------------------------------

A free-threaded interpreter is more permissive at
import: an undeclared extension still loads, but
CPython logs a warning per extension. The application
runs, but its correctness under concurrent access has
not been audited. Typical declaration::

    static PyModuleDef_Slot module_slots[] = {
        {Py_mod_exec, exec_module},
        {Py_mod_gil, Py_MOD_GIL_NOT_USED},
        {0, NULL}
    };

mod_wsgi sets ``PyConfig.enable_gil`` explicitly to
disable the GIL when ``WSGIFreeThreading`` is on, so
the import permissiveness comes from CPython's
``_PyConfig_GIL_DISABLE`` policy rather than from
mod_wsgi-side filtering.

Auditing checklist:

* Consider every C extension transitively imported,
  not just top-level dependencies. Extensions pulled
  in by SDKs (database drivers, serialisers,
  monitoring agents) are easy to miss.
* Pure Python modules are unaffected by either mode.
* Native code linked into Python via ``ctypes`` or
  ``cffi`` is not subject to the declaration check;
  its thread-safety has to meet the mode's
  requirements independently.

Using these directives under mod_wsgi-express
=============================================

``mod_wsgi-express`` does not have first-class command
line options for ``WSGIFreeThreading``,
``WSGIPerInterpreterGIL`` or
``WSGIInterpreterOptions``. The supported path is
``--include-file``, which appends a file of Apache
directives at the end of the generated configuration.
``--include-file`` is repeatable, so several
fragments can be combined.

Free-threading
--------------

A one-line include file::

    # /tmp/freethreading.conf
    WSGIFreeThreading On

invoked as::

    mod_wsgi-express start-server wsgi.py \
        --processes 1 --threads 30 \
        --include-file /tmp/freethreading.conf

``mod_wsgi-express`` always creates one daemon process
group, so a top-level ``WSGIFreeThreading On`` applies
to both that daemon group and the embedded interpreter
the Apache child uses for any auth or dispatch
scripts.

Per-interpreter GIL
-------------------

Same shape::

    # /tmp/per-interp-gil.conf
    WSGIPerInterpreterGIL On

with::

    mod_wsgi-express start-server wsgi.py \
        --processes 1 --threads 15 \
        --application-group %{ENV:APPLICATION_GROUP} \
        --include-file /tmp/per-interp-gil.conf

The ``--application-group %{ENV:APPLICATION_GROUP}``
option pairs with a ``WSGIDispatchScript`` to route
each request to a chosen sub interpreter. Both pieces
can live in the same include file::

    # /tmp/dispatch.conf
    WSGIPerInterpreterGIL On
    WSGIDispatchScript /tmp/dispatch.py

then::

    mod_wsgi-express start-server wsgi.py \
        --processes 1 --threads 15 \
        --application-group %{ENV:APPLICATION_GROUP} \
        --include-file /tmp/dispatch.conf

The
:doc:`../configuration-directives/WSGIPerInterpreterGIL`
page has the full dispatch-script example.

Scoped configuration via WSGIInterpreterOptions
-----------------------------------------------

When the configuration calls for a
``<WSGIInterpreterOptions>`` container (for example to
opt only the daemon group into free-threading while
the embedded interpreter stays on the shared GIL),
write the container into the include file directly and
target the daemon group by name. Use Express's
``--process-group NAME`` option to give the daemon
group a stable name to refer to::

    # /tmp/daemon-freethreading.conf
    <WSGIInterpreterOptions process-group=myapp>
        WSGIFreeThreading On
    </WSGIInterpreterOptions>

invoked as::

    mod_wsgi-express start-server wsgi.py \
        --process-group myapp \
        --processes 1 --threads 30 \
        --include-file /tmp/daemon-freethreading.conf

Without ``--process-group``, Express names the daemon
group after the listening host and port (for example
``localhost:8000``). The generated name is still usable
as a selector, but ``--process-group`` makes the
configuration deterministic and easier to script
around.

Choosing a mode
===============

There is no universal answer; the right choice depends
on the workload and the C extension surface. Rough
guidance:

* The shared-GIL configuration with multiple daemon
  processes is the right default for almost every
  deployment. Concurrency across requests comes from
  running multiple processes, which sidesteps the GIL
  and the audit cost of either opt-in mode. Reach for
  the alternatives only when there is a clear reason
  to.

* Choose per-interpreter GIL when the application is
  CPU-bound, an audit of every loaded C extension for
  PEP 489 multi-interpreter support is feasible, and
  the deployment shape calls for parallel execution
  inside a single process (for example to share a
  large in-process resource across requests without
  inter-process synchronisation). Pair it with a
  dispatch script to route requests across the named
  sub interpreters.

* Choose free-threading when every C extension in the
  loaded set has been audited for the no-GIL runtime
  and the application can take advantage of
  intra-process parallelism without the
  per-sub-interpreter isolation that PEP 684 offers.
  Free-threading is the most permissive at import
  time but the highest risk to in-process invariants.

* In a hybrid environment, split the workload across
  daemon process groups by mode rather than trying to
  pick one mode for everything.

Cross-references
================

* :doc:`../configuration-directives/WSGIFreeThreading`
* :doc:`../configuration-directives/WSGIPerInterpreterGIL`
* :doc:`../configuration-directives/WSGIInterpreterOptions`
* :doc:`../configuration-directives/WSGISwitchInterval`
* :doc:`../configuration-directives/WSGIDaemonProcess`
* :doc:`../configuration-directives/WSGIDispatchScript`
* :doc:`processes-and-threading`
* :doc:`embedded-and-daemon-mode`
* :doc:`mod-wsgi-express-quickstart`
