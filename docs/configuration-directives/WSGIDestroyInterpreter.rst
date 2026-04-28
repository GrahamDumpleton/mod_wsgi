======================
WSGIDestroyInterpreter
======================

:Description: Enable/disable cleanup of Python interpreter.
:Syntax: ``WSGIDestroyInterpreter On|Off``
:Default: ``WSGIDestroyInterpreter On``
:Context: server config

The ``WSGIDestroyInterpreter`` directive is used to control whether the Python
interpreter is destroyed when processes are shutdown or restarted. By default
the Python interpreter is destroyed when the process is shutdown or restarted.

This directive was added due to changes in Python 3.9 where the Python cleanup
behaviour was changed such that it would wait on daemon threads to complete.
This could cause cleanup of the Python interpreter to hang in some cases
where threads were created external to Python, as is the case where Python
is embedded in a C program such as mod_wsgi with Apache.

If you observe daemon processes hanging at shutdown or restart, set this
directive to ``Off`` to skip Python interpreter destruction::

  WSGIDestroyInterpreter Off

Skipping interpreter destruction means Python ``atexit`` handlers and any
other code registered to run during interpreter finalisation will not run.
For most WSGI applications this is acceptable, since the daemon process is
about to exit anyway and the operating system will reclaim its resources.
