=============
Version 4.5.8
=============

Version 4.5.8 of mod_wsgi can be obtained from:

  https://codeload.github.com/GrahamDumpleton/mod_wsgi/tar.gz/4.5.8

Bugs Fixed
----------

* When using HTTP/2 support and ``wsgi.file_wrapper``, the response could
  be truncated when ``mod_h2`` was deferring the sending of the response
  until after the WSGI request had been finalized.
