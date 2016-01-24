==============
WSGIPythonEggs
==============

:Description: Directory to use for Python eggs cache.
:Syntax: ``WSGIPythonEggs`` *directory*
:Context: server config

Used to specify the directory to be used as the Python eggs cache directory
for all sub interpreters created within embedded mode. This directive
achieves the same affect as having set the ``PYTHON_EGG_CACHE``
environment variable.

Note that the directory specified must exist and be writable by the user
that the Apache child processes run as. The directive only applies to
mod_wsgi embedded mode. To set the Python eggs cache directory for mod_wsgi
daemon processes, use the 'python-eggs' option to the WSGIDaemonProcess
directive instead.
