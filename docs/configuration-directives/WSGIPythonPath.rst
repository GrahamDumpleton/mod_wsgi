==============
WSGIPythonPath
==============

:Description: Additional directories to search for Python modules.
:Syntax: ``WSGIPythonPath`` *directory|directory-1:directory-2:...*
:Context: server config

Used to specify additional directories to search for Python modules. If
multiple directories are specified they should be separated by a ':' if
using a UNIX like system, or ';' if using Windows. If any part of a
directory path contains a space character, the complete argument string to
WSGIPythonPath must be quoted.

When using mod_wsgi version 1.X, this directive is the same as having set
the environment variable ``PYTHONPATH`` in the environment of the user
that Apache executes as. If this directive is used it will override any
setting of ``PYTHONPATH`` in the environment of the user that Apache
executes as. The end result is that the listed directories will be added
to ``sys.path``.

Note that in mod_wsgi version 1.X this applies to all Python sub
interpreters created, be they in the Apache child processes when embedded
mode is used, or in distinct daemon processes when daemon mode is used. It
is not possible to define this differently for mod_wsgi daemon processes.
If additional directories need to be added to the module search path for a
specific WSGI application it should be done within the WSGI application
script itself.

When using mod_wsgi version 2.0, this directive does not have the same
affect as having set the environment variable ``PYTHONPATH``. In fact, if
``PYTHONPATH`` is set in the environment of the user that Apache is
started as, any directories so defined will still be added to
``sys.path`` and they will not be overridden.

The difference with this directive when using mod_wsgi 2.0 is that each
directory listed will be added to the end of ``sys.path`` by calling
``site.addsitedir()``. By using this function, as well as the directory
being added to ``sys.path``, any '.pth' files located in the directories
will be opened and processed. Thus, if the directories contain Python eggs,
any associated directories corresponding to those Python eggs will in turn
also be added automatically to ``sys.path``.

Note however that when using mod_wsgi 2.0, this directive only sets up the
additional Python module search directories for interpreters created in the
Apache child processes where embedded mode is used. If directories need to
be specified for interpreters running in daemon processes, the
'python-path' option to the WSGIDaemonProcess directive corresponding to
that daemon process should instead be used.

In mod_wsgi version 2.0, because directories corresponding to Python eggs
are automatically added to ``sys.path``, the directive can be used to
point at the ``site-packages`` directory corresponding to a Python
virtual environment created by a tool such as ``virtualenv``.

For mod_wsgi 1.X, this directive will have no affect if mod_python is being
loaded into Apache at the same time as mod_wsgi as mod_python will in that
case be responsible for initialising Python.

