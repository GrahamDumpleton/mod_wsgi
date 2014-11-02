=============
Version 4.3.1
=============

Version 4.3.1 of mod_wsgi can be obtained from:

  https://github.com/GrahamDumpleton/mod_wsgi/archive/4.3.1.tar.gz

Known Issues
------------

1. The makefiles for building mod_wsgi on Windows are currently broken and
need updating. As most new changes relate to mod_wsgi daemon mode, which is
not supported under Windows, you should keep using the last available
binary for version 3.X on Windows instead.

Bugs Fixed
----------

1. The ``install-module`` sub command of ``mod_wsgi-express`` was incorrectly
trying to install the mod_wsgi ``.so`` file onto itself rather than into
the Apache modules directory.

2. The workaround for the broken MacOS X Apache build scripts as implemented
by the ``configure`` script used when building using the traditional make
command wasn't working correctly for MacOS X 10.10 (Yosemite).

In fixing this issue, the ``configure`` script has been enhanced such that
it is now no longer to have the whole of the Xcode package installed on
MacOS X. Instead the minimum required now is the developer command line
tools. If using Python and you wanted to be able to install Python packages
which has a source code component you would have already likely installed
the developer command line tools.

New Features
------------

1. Added the ``--add-handler`` option to ``mod_wsgi-express`` to allow a
WSGI application script file to be provided which is to handle any requests
against static resources in the document root directory matching a specific
extension type.

2. Added a mechanism to limit the amount of response content that can
buffered in the Apache child worker processes when proxying back the response
from a request which had been handled in a mod_wsgi daemon process.

This is to combat a lack of flow control within Apache 2.2 which can cause
excessive amounts of memory usage as a result of such buffered content.
This issue in Apache 2.2 was fixed in Apache 2.4, but the new mechanism is
applied to both versions for consistency.

The default maximum on the amount of buffered content is 65536 bytes. This
can be increased by using the ``proxy-buffer-size`` option to the
``WSGIDaemonProcess`` directive or the ``--proxy-buffer-size`` option to
``mod_wsgi-express``. If using Apache 2.4, its own flow control mechanism
may override the value in increasing the buffer size.
