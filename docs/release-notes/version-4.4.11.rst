==============
Version 4.4.11
==============

Version 4.4.11 of mod_wsgi can be obtained from:

  https://codeload.github.com/GrahamDumpleton/mod_wsgi/tar.gz/4.4.11

For details on the availability of Windows binaries see:

  https://github.com/GrahamDumpleton/mod_wsgi/tree/master/win32

Bugs Fixed
----------

1. No provision was made for operating systems with a very low limit on the
number of separate data blocks that could be passed to system ``writev()``
call. This was an issue on Solaris where the limit is 16 and meant that since
version 4.4.0, daemon mode of mod_wsgi would fail where a HTTP request had
more than a small number of headers.

New Features
------------

1. Added the ``--service-log`` option to ``mod_wsgi-express`` for
specifying the name of a log file for a specific service script. The
arguments are the name of the service and the file name for the log. The
log file will be placed in the log directory, be it the default, or a
specific log directory if specified.
