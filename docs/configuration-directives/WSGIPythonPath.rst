==============
WSGIPythonPath
==============

:Description: Additional directories to search for Python modules.
:Syntax: ``WSGIPythonPath`` *directory|directory-1:directory-2:...*
:Context: server config

Used to specify additional directories to search for Python modules when
running WSGI applications in embedded mode. If multiple directories are
specified they should be separated by a ``:`` on UNIX-like systems, or
``;`` on Windows. If any part of a directory path contains a space
character, the complete argument string to ``WSGIPythonPath`` must be
quoted.

For example, to add a single directory to the module search path::

  WSGIPythonPath /usr/local/wsgi/site-packages

Each directory listed is added to the end of ``sys.path`` by calling
``site.addsitedir()``. Because that function is used, any ``.pth`` files
located in the directories will also be opened and processed. This means
the directive can also be pointed at the ``site-packages`` directory of
a Python virtual environment so that the packages installed there are
visible to the embedded interpreter.

If ``PYTHONPATH`` is also set in the environment of the user that Apache
is started as, any directories defined there will still be added to
``sys.path`` and will not be overridden.

This directive only affects interpreters created in Apache child
processes when embedded mode is used. To set additional Python module
search directories for interpreters running in daemon processes, use
the ``python-path`` option to the WSGIDaemonProcess directive instead.

For most modern deployments, daemon mode is the preferred deployment
method, in which case configure the Python search path via
WSGIDaemonProcess rather than this directive.
