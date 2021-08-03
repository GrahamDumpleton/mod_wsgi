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

* When using CMMI (configure/make/make install) method for compiling mod_wsgi
  if embedded mode was being disabled at compile time, compilation would fail.

Features Changed
----------------

* Historically when using embedded mode, ``wsgi.multithread`` in the WSGI
  ``environ`` dictionary has reported ``True`` when any multithread capable
  Apache MPM were used (eg., worker, event), even if the current number of
  configured threads per child process was overridden to be 1. Why this was
  the case has been forgotten, but generally wouldn't matter since no one
  would ever set up Apache with a mulithread MPM and then configure the
  number of threads to be 1. If that was desired then ``prefork`` MPM would
  be used.

  With ``mod_wsgi-express`` since 4.8.0 making it much easier to use
  embedded mode and have a sane configuration used, since it is generated
  for you, the value of ``wsgi.multithread`` has been changed such that it
  will now correctly report ``False`` if using embedded mode, a multithread
  capable MPM is used, but the number of configured threads is set to 1.
