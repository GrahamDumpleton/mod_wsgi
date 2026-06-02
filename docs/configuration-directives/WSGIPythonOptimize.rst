==================
WSGIPythonOptimize
==================

:Description: Enables basic Python optimisation features.
:Syntax: ``WSGIPythonOptimize [0|1|2]``
:Default: ``WSGIPythonOptimize 0``
:Context: server config

Sets the Python interpreter's optimisation level. This is the embedded
equivalent of the ``-O`` and ``-OO`` command-line options to the
``python`` executable.

* **0** (default): no optimisations applied.
* **1** (equivalent to ``-O``): ``assert`` statements are skipped and
  ``__debug__`` is set to ``False``.
* **2** (equivalent to ``-OO``): everything from level 1, plus
  docstrings are stripped from the bytecode. Some Python packages
  inspect docstrings at runtime and may fail under this level.

For example::

  WSGIPythonOptimize 1

Note that this only affects bytecode that mod_wsgi causes to be
compiled while the application runs. Bytecode files that already
exist on disk for the standard library or installed packages are
reused as-is, regardless of the level set here. As a result, the
practical effect on memory or performance is usually small.

Code that depends on ``assert`` statements for runtime validation
will silently change behaviour at level 1 or higher.
