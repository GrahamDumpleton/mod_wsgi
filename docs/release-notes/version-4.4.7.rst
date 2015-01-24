=============
Version 4.4.7
=============

Version 4.4.7 of mod_wsgi can be obtained from:

  https://codeload.github.com/GrahamDumpleton/mod_wsgi/tar.gz/4.4.7

For details on the availability of Windows binaries see:

  https://github.com/GrahamDumpleton/mod_wsgi/tree/master/win32

New Features
------------

1. Added ``--service-script`` option to ``mod_wsgi-express`` to allow a
Python script to be loaded and executed in the context of a distinct
daemon process. This can be used for executing a service to be managed by
Apache, even though it is a distinct application.
