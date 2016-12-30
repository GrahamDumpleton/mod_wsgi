==============
Version 4.5.12
==============

Version 4.5.12 of mod_wsgi can be obtained from:

  https://codeload.github.com/GrahamDumpleton/mod_wsgi/tar.gz/4.5.12

New Features
------------

* When using ``pip install`` on Windows, in addition to looking in the
  directory ``C:\Apache24`` for an Apache installation, it will now also
  check ``C:\Apache22`` and ``C:\Apache2``. It is recommended though that
  you use Apache 2.4. If your Apache installation is elsewhere, you can
  still set the ``MOD_WSGI_APACHE_ROOTDIR`` environment variable to its
  location. The environment variable should be set in your shell before
  running ``pip install mod_wsgi`` and should be set in a way that exports
  it to child processes run from the shell.
