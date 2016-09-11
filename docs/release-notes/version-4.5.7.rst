=============
Version 4.5.7
=============

Version 4.5.7 of mod_wsgi can be obtained from:

  https://codeload.github.com/GrahamDumpleton/mod_wsgi/tar.gz/4.5.7

Bugs Fixed
----------

1. Resolved problem whereby mod_wsgi would fail on startup when using
   Anaconda Python. This was caused by Anaconda Python changing the
   behaviour of the C API function ``Py_GetVersion()`` so that it can no
   longer be called before the Python interpreter is initialised. Now
   display only the Python major and minor version in server string from
   time of compilation, rather than runtime. Also no longer log warning
   about mismatches between compile time and runtime Python version. This
   avoids need to call ``Py_GetVersion()``.

New Features
------------

1. Add ``--http2`` option to ``mod_wsgi-express`` for enabling support of
   HTTP/2. Requires the ``mod_http2`` module to be compiled into Apache
   httpd server for versions of Apache where that is available.
