======================
WSGIInterpreterOptions
======================

:Description: Container for per-interpreter configuration directives.
:Syntax: ``<WSGIInterpreterOptions [process-group=NAME] [application-group=NAME]> ... </WSGIInterpreterOptions>``
:Context: server config

Section directive that scopes a set of per-interpreter configuration
directives to interpreters matching the supplied selector keys. The
container exists so that properties of an individual Python sub
interpreter (or set of sub interpreters) can be configured
independently of the process-wide defaults.

Example::

  <WSGIInterpreterOptions process-group=daemon-1 application-group=app1>
      WSGIPerInterpreterGIL On
      WSGISwitchInterval 0.002
      WSGIPythonPath /opt/app1/lib
  </WSGIInterpreterOptions>

Selectors
---------

Both ``process-group=`` and ``application-group=`` are optional.
Omitting a key means the container matches any value for that
dimension. The empty container ``<WSGIInterpreterOptions>`` matches
every interpreter.

The ``process-group=`` value matches against the name of a
``WSGIDaemonProcess`` group, or against the empty string for embedded
mode interpreters created in Apache child processes.

The ``application-group=`` value matches against the resolved
application group name at interpreter-creation time. So
``application-group=app1`` matches when a ``WSGIApplicationGroup app1``
directive (or equivalent ``application-group=`` parameter on
``WSGIScriptAlias``, ``WSGIImportScript`` or ``WSGIHandlerScript``)
selects ``app1``.

The literal value ``%{GLOBAL}`` is accepted as a synonym for the
empty string on **both** selectors. On ``application-group=`` it
matches the main Python interpreter. On ``process-group=`` it matches
embedded mode (Apache child processes that have not been routed to a
daemon group).

Variable-expanded application group names of the form ``%{ENV:VAR}``
are resolved at request time, after the configuration has been loaded,
and the container match is evaluated then.

Permitted child directives
--------------------------

Only the following directives are valid inside the container:

* :doc:`WSGIPerInterpreterGIL`
* :doc:`WSGIFreeThreading`
* :doc:`WSGISwitchInterval`
* :doc:`WSGIPythonPath`
* :doc:`WSGIRestrictStdin`
* :doc:`WSGIRestrictStdout`
* :doc:`WSGIRestrictSignal`

Any other directive placed inside the container is a configuration
error.

When a directive listed above appears at server config scope without
being inside a container, it continues to behave as documented on its
own page. Containers are purely additive; existing configurations
continue to work unchanged.

Inheritance and merge rules
---------------------------

When an interpreter is created, mod_wsgi walks every container
defined at server config scope and selects those whose selectors match
the interpreter's resolved process group and application group names.

Each matching container has a specificity score equal to the count of
non-wildcard selector keys: 0 for ``<WSGIInterpreterOptions>``, 1 for
a single-key container, 2 for one with both keys set. Top-level
directives outside any container are treated as the lowest layer.

For the scalar directives (``WSGIPerInterpreterGIL``,
``WSGISwitchInterval``, ``WSGIRestrictStdin``, ``WSGIRestrictStdout``,
``WSGIRestrictSignal``) the most-specific matching layer wins. If two
matching containers share the same specificity, the one written later
in the configuration wins. If no container matches, the top-level
value applies.

For ``WSGIPythonPath`` every matching layer contributes. See
`WSGIPythonPath layering`_ below.

``WSGIFreeThreading`` is resolved separately from the per-interpreter
directives because free-threading is a process-wide setting fixed at
``Py_InitializeFromConfig`` time. The resolver walks containers
matching the current process's ``process-group=`` selector only;
containers with ``application-group=`` set are skipped (and warned
at config load). The resolved value drives ``PyConfig.enable_gil``
and is then read back by sub interpreter creation and switch
interval sites to suppress configuration that has no effect when
the GIL is disabled. See :doc:`WSGIFreeThreading` for the full
rules.

WSGIPythonPath layering
-----------------------

``WSGIPythonPath`` is additive across matching layers rather than
last-write-wins. Each layer's directory list is processed in turn,
least-specific first, most-specific last. For each directory in a
layer mod_wsgi calls ``site.addsitedir()`` so that any ``.pth`` files
in that directory are processed normally, then hoists the entries
that ``site.addsitedir()`` added to the front of ``sys.path``.

Because layers are applied least-specific to most-specific and each
hoist places entries at the front, the most-specific layer's
directories end up at the very front of ``sys.path`` once all layers
have been applied.

The base layer for ``WSGIPythonPath`` depends on which interpreter is
being created:

* For embedded mode interpreters the base layer is the top-level
  ``WSGIPythonPath`` directive, if set.
* For daemon mode interpreters the base layer is the ``python-path=``
  parameter on the matching ``WSGIDaemonProcess`` directive, if set.

The container's ``WSGIPythonPath`` is purely additive on top of the
applicable base layer. It never replaces the base layer. To use a
different base in daemon mode, set ``python-path=`` on the
``WSGIDaemonProcess`` directive.

The empty container::
  
  <WSGIInterpreterOptions>
  WSGIPythonPath /opt/lib
  </WSGIInterpreterOptions>
 
adds ``/opt/lib`` to both embedded and daemon interpreters, which is
something there is no way to express with a single top-level directive.

Switch interval validation
--------------------------

A ``WSGIPerInterpreterGIL`` setting only changes the GIL configuration
of sub interpreters. Under the shared GIL the Python interpreter's
switch interval is a process-global value: every interpreter in the
process sees the same switch interval, regardless of which one
``sys.setswitchinterval()`` is called from.

Setting ``WSGISwitchInterval`` inside a container that selects on
``application-group=`` therefore requires that the matching interpreter
also resolves to per-interpreter GIL after the merge. Otherwise the
directive would appear to be application-group-scoped while silently
mutating the process-global value.

For statically-named ``application-group=`` containers the check runs
at configuration load. For ``application-group=%{ENV:VAR}`` containers
the check runs at sub-interpreter creation time; if the check fails
the switch interval setting is skipped for that interpreter and a
warning is logged. The request itself still proceeds.

Containers selecting only on ``process-group=`` (or with no selectors
at all) are always safe with ``WSGISwitchInterval``, because every
interpreter in the matched scope shares whatever GIL configuration is
in force.

Examples
--------

Process-wide opt-in to per-interpreter GIL::

  WSGIPerInterpreterGIL On

Per-interpreter GIL only for a single application group, leaving the
rest of the process on the shared GIL::

  <WSGIInterpreterOptions application-group=app1>
      WSGIPerInterpreterGIL On
  </WSGIInterpreterOptions>

Per-interpreter GIL for every interpreter in a named daemon process
group::

  <WSGIInterpreterOptions process-group=daemon-1>
      WSGIPerInterpreterGIL On
  </WSGIInterpreterOptions>

Tuning the GIL switch interval for one application that has its own
GIL, while leaving the rest of the process untouched::

  <WSGIInterpreterOptions application-group=app1>
      WSGIPerInterpreterGIL On
      WSGISwitchInterval 0.001
  </WSGIInterpreterOptions>

Adding a directory to ``sys.path`` for one application without
disturbing the daemon-wide path::

  WSGIDaemonProcess daemon-1 python-path=/opt/daemon-1
  <WSGIInterpreterOptions process-group=daemon-1 application-group=app1>
      WSGIPythonPath /opt/app1/src:/opt/app1/lib
  </WSGIInterpreterOptions>

Restricting ``sys.stdout`` for a single application group while
leaving the process default unchanged::

  <WSGIInterpreterOptions application-group=app1>
      WSGIRestrictStdout On
  </WSGIInterpreterOptions>
