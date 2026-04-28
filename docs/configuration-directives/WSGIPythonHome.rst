==============
WSGIPythonHome
==============

:Description: Absolute path to Python prefix/exec_prefix directories.
:Syntax: ``WSGIPythonHome`` *prefix|prefix:exec_prefix*
:Context: server config

Used to indicate to Python where its library files are installed. This
is needed when the Python executable is not on the ``PATH`` of the user
that Apache runs as, or where a system has multiple versions of Python
installed in different locations and the version that Apache finds first
on its ``PATH`` is not the one mod_wsgi was built against.

This directive can also be used to point at a Python virtual environment
so that the whole of mod_wsgi runs against it. For most modern
deployments the equivalent ``home`` option to the WSGIDaemonProcess
directive is preferred, since daemon mode is the standard deployment
model and that option only affects the daemon process group.

When this directive is used it should be supplied with the prefix for
the directories containing the platform-independent and platform-specific
Python library files. The two directories should be separated by a
``:``. If the same directory is used for both, only one path needs to
be supplied. The value is normally what ``sys.prefix`` reports for the
Python installation in question.

The Python installation referred to by this directive must be the same
major/minor version of Python that mod_wsgi was compiled against. To
use a different major/minor version, mod_wsgi must be rebuilt against
that version.

This directive is the same as setting the environment variable
``PYTHONHOME`` in the environment of the user that Apache executes as.
If the directive is used it overrides any setting of ``PYTHONHOME`` in
that environment.

This directive is not available on Windows. On Windows, Python ignores
``PYTHONHOME`` and instead determines the location of its library files
from the location of the Python DLL.
