=============
Version 4.6.7
=============

Version 4.6.7 of mod_wsgi can be obtained from:

  https://codeload.github.com/GrahamDumpleton/mod_wsgi/tar.gz/4.6.7

Bugs Fixed
----------

* Fix Windows build errors due to Python 3.7+ not providing empty function
  stubs for ``PyOS_AfterFork_Child()`` and ``PyOS_AfterFork_Parent()``.
