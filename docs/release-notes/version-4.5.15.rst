==============
Version 4.5.15
==============

Version 4.5.15 of mod_wsgi can be obtained from:

  https://codeload.github.com/GrahamDumpleton/mod_wsgi/tar.gz/4.5.15

Bugs Fixed
----------

* Incorrect version for mod_wsgi was being reported in server token.

* On 32 bit platforms, when reading from request content, all input would
  be returned and the chunk size would be ignored.
