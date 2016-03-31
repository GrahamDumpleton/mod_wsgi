==============
WSGIPythonHome
==============

:Description: Absolute path to Python prefix/exec_prefix directories.
:Syntax: ``WSGIPythonHome`` *prefix|prefix:exec_prefix*
:Context: server config

Used to indicate to Python when it is initialised where its library files
are installed. This should be defined where the Python executable is not in
the ``PATH`` of the user that Apache runs as, or where a system has
multiple versions of Python installed in different locations in the file
system, especially different installations of the same major/minor version,
and the installation that Apache finds in its ``PATH`` is not the desired
one.

This directive can also be used to indicate a Python virtual environment
created using a tool such as ``virtualenv``, to be used for the whole of
mod_wsgi.

When this directive is used it should be supplied the prefix for the
directories containing the platform independent and system dependent Python
library files. The directories should be separated by a ':'. If the same
directory is used for both, then only the one directory path needs to be
supplied. Where the directories are the same, this can usually be
determined by looking at the value of the ``sys.prefix`` variable for the
version of Python being used.

Note that the Python installation being referred to using this directive
must be the same major/minor version of Python that mod_wsgi was compiled
for. If you want to use a different version of major/minor version of
Python than currently used, you must recompile mod_wsgi against the alternate
version of Python.

This directive is the same as having set the environment variable
``PYTHONHOME`` in the environment of the user that Apache executes as. If
this directive is used it will override any setting of ``PYTHONHOME`` in
the environment of the user that Apache executes as.

This directive will have no affect if mod_python is being loaded into Apache
at the same time as mod_wsgi as mod_python will in that case be responsible
for initialising Python.

This directive is not available on Windows systems. Note that mod_wsgi 1.X
will not actually reject this directive if listed in the configuration,
however, it also will not do anything either. This is because on Windows
systems Python ignores the ``PYTHONHOME`` environment variable and always
seems to use the location of the Python DLL for determining where the
library files are located.

