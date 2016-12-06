=============
Version 4.5.10
=============

Version 4.5.10 of mod_wsgi can be obtained from:

  https://codeload.github.com/GrahamDumpleton/mod_wsgi/tar.gz/4.5.10

Bugs Fixed
----------

* In version 4.5.9, the version number 4.5.8 was being incorrectly reported
  via ``mod_wsgi.version`` in the per request WSGI environ dictionary.

* When using Anaconda Python on MacOS X, the Python shared library wasn't
  being resolved correctly due to changes in Anaconda Python, meaning it
  cannot be used in embedded systems which load Python via a dynamically
  loaded module, such as in Apache. When using ``mod_wsgi-express`` the
  Python shared library is now forcibly loaded before the mod_wsgi module
  is loaded in Apache. If doing manual Apache configration, you will need
  to add before the ``LoadModule`` line for ``wsgi_module``, a ``LoadFile``
  directive which loads the Ananconda Python shared library by its full
  path from where it is located in the Anaconda Python ``lib`` directory.
