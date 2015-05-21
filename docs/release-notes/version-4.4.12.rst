==============
Version 4.4.12
==============

Version 4.4.12 of mod_wsgi can be obtained from:

  https://codeload.github.com/GrahamDumpleton/mod_wsgi/tar.gz/4.4.12

For details on the availability of Windows binaries see:

  https://github.com/GrahamDumpleton/mod_wsgi/tree/master/win32

Bugs Fixed
----------

1. If the WSGI application when run under daemon mode returned response
content as many small blocks, this could result in excessive memory
usage in the Apache child worker process proxying the request due to
many buckets being buffered until the buffer size threshold was reached.
If the number of buckets reaches a builtin threshold the buffered data
will now be forcibly flushed even if the size threshold hadn't been
reached.
