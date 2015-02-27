==============
Version 4.4.10
==============

Version 4.4.10 of mod_wsgi can be obtained from:

  https://codeload.github.com/GrahamDumpleton/mod_wsgi/tar.gz/4.4.10

For details on the availability of Windows binaries see:

  https://github.com/GrahamDumpleton/mod_wsgi/tree/master/win32

Bugs Fixed
----------

1. Fixed a reference counting bug which would cause a daemon process to
crash if both ``home`` and ``python-path`` options were specified at the
same time with the ``WSGIDaemonProcess`` directive.

Features Changed
----------------

1. When specifying a service script with the ``--service-script`` option of
``mod_wsgi-express``, the home directory for the process will now be set to
the same home directory as used for the hosted WGSI application. Python
modules from the WSGI application will therefore be automatically found
when imported. Any directory paths added using ``--python-path`` option
will also be added as search directories for Python module imports, with
any ``.pth`` files in those directories also being handled. In addition,
the language locale and Python eggs directory used by the hosted WSGI
application will also be used for the service script.

2. When specifying ``--python-path`` option, when paths are now setup for
the WSGI application, they will be added in such a way that they appear at
the head of ``sys.path`` and any ``.pth`` files in those directories are
also handled.

New Features
------------

1. Added the ``--directory-listing`` option to ``mod_wsgi-express`` to
allow automatic directory listings to be enabled when using the static file
application type and no explicit directory index file has been specified.
