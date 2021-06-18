=============
Version 4.9.0
=============

Version 4.9.0 of mod_wsgi can be obtained from:

  https://codeload.github.com/GrahamDumpleton/mod_wsgi/tar.gz/4.9.0

Bugs Fixed
----------

* The mod_wsgi code wouldn't compile on Python 3.10 as various Python C API
  functions were removed. Note that the changes required switching to
  alternate C APIs. The changes were made for all Python versions back to
  Python 3.6 and were not conditional on Python 3.10+ being used. This is
  why the minor version got bumped.
