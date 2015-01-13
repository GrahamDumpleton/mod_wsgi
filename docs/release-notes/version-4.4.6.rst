=============
Version 4.4.6
=============

Version 4.4.6 of mod_wsgi can be obtained from:

  https://codeload.github.com/GrahamDumpleton/mod_wsgi/tar.gz/4.4.6

For details on the availability of Windows binaries see:

  https://github.com/GrahamDumpleton/mod_wsgi/tree/master/win32

Bugs Fixed
----------

1. Apache 2.2.29 and 2.4.11 introduce additional fields to the request
structure ``request_rec`` due to CVE-2013-5704. The addition of these
fields will cause versions of mod_wsgi from 4.4.0-4.4.5 to crash when used
in mod_wsgi daemon mode and mod_wsgi isn't initialising the new structure
members. If updating to those Apache versions or newer, you must update
to mod_wsgi version 4.4.6 or newer. The mod_wsgi source code must have also
been compiled against the newer Apache version. You cannot compile mod_wsgi
version 4.4.6 source code against an older Apache version and then upgrade
Apache to the newer versions as initialising of the new structure members
will not have been compiled in as whether it is done is dependent on the
version of Apache being used at compile time.

2. Override ``LC_ALL`` environment variable when ``locale`` option to the
``WSGIDaemonProcess`` directive. It is not always sufficient to just call
``setlocale()`` as some Python code, including interpreter initialisation
can still consult the original ``LC_ALL`` environment variable. In this
case this can result in an undesired file system encoding still being
selected.

New Features
------------

1. Added ``--enable-gdb`` option to ``mod_wsgi-express`` for when running
in debug mode. With this option set, Apache will be started up within
``gdb`` allowing the debug of process crashes on startup or while handling
requests. If the ``gdb`` program is not in ``PATH``, the ``--gdb-executable``
option can be set to give its location.
