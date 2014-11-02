=============
Version 4.2.8
=============

Version 4.2.8 of mod_wsgi can be obtained from:

  https://github.com/GrahamDumpleton/mod_wsgi/archive/4.2.8.tar.gz

Known Issues
------------

1. The makefiles for building mod_wsgi on Windows are currently broken and
need updating. As most new changes relate to mod_wsgi daemon mode, which is
not supported under Windows, you should keep using the last available
binary for version 3.X on Windows instead.

Bugs Fixed
----------

1. Disable feature for dumping stack traces on daemon process shutdown when
a timeout occurs when using Python prior to 2.5. This is because the C API
functions are not available in older Python versions.

2. If using Python 3.4 the minimum MacOS X version you can use is 10.8.
This needs to be inforced as Apache Runtime library has a definition in
header files which changes sizes from 10.7 to 10.8 and trying to compile
for compatability back to 10.6 as Python 3.4 tries to enforce, will cause
mod_wsgi daemon mode processes to crash at runtime.

3. Python 3.3+ pyvenv style virtual environments would not work with
mod_wsgi via the ``WSGIPythonHome`` directive or the ``home`` option to the
``WSGIDaemonProcess`` directive. This is because the support in Python for
pyvenv will not work with embedded systems which set the equivalent of
``PYTHONHOME`` via the Python C API.

The underlying problem in Python is described in issue:

  * http://bugs.python.org/issue22213

of the Python issue tracer.

To support both normal virtualenv style virtual environments and pyvenv
style virtual environments, the manner in which virtual environments are
setup by mod_wsgi has been changed. This has at this point only been done
on UNIX systems however, as it isn't known at this point whether the same
trick will work on Windows systems.
