==============
Version 4.5.23
==============

Version 4.5.23 of mod_wsgi can be obtained from:

  https://codeload.github.com/GrahamDumpleton/mod_wsgi/tar.gz/4.5.23

Bugs Fixed
----------

* Incorrect check around whether ``apxs`` was present on system would result
  in ``pip`` install failing on Windows, and possibly also when using
  latest Xcode on MacOS X.
