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
This could cause cleanup of the Python interpreter to hang in the some cases
where threads were created external to Python, as is the case where Python is
embedded in a C program such as mod_wsgi with Apache.

This problem of hanging when cleanup of the Python interpreter was attempted
was especially noticeable when using mod_wsgi to host Trac.

Note that it is not known whether versions of Python newer than 3.9 still have
this problem or whether further changes were made in Python interpreter cleanup
code.
