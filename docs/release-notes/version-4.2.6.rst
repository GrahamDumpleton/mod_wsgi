=============
Version 4.2.6
=============

Version 4.2.6 of mod_wsgi can be obtained from:

  https://github.com/GrahamDumpleton/mod_wsgi/archive/4.2.6.tar.gz

Known Issues
------------

1. The makefiles for building mod_wsgi on Windows are currently broken and
need updating. As most new changes relate to mod_wsgi daemon mode, which is
not supported under Windows, you should keep using the last available
binary for version 3.X on Windows instead.

Bugs Fixed
----------

1. Apache 2.2.3 and older doesn't provide the ap_get_server_description()
function. Using mod_wsgi with such older versions would therefore cause
processes to crash when Apache was being started up. For older versions of
Apache now fallback to using ap_get_server_version() instead.
