=============
Version 4.7.0
=============

Version 4.7.0 of mod_wsgi can be obtained from:

  https://codeload.github.com/GrahamDumpleton/mod_wsgi/tar.gz/4.7.0

New Features
------------

* Now releasing parallel ``mod_wsgi-standalone`` package to PyPi. This is
  the same as the ``mod_wsgi`` package, except that by installing the
  ``mod_wsgi-standalone`` package, it will automatically trigger the
  ``mod_wsgi-httpd`` package to install the Apache HTTPD server as part
  of your Python installation. When you run ``mod_wsgi-express`` it will
  use that Apache HTTPD server installation.

  The ``mod_wsgi-standalone`` package is required where you need to install
  ``mod_wsgi-express`` using its own Apache HTTPD installation due to no
  system Apache HTTPD server package being available, and the installation
  needs to be done using a ``requirements.txt`` file for ``pip`` or other
  package install manager. Using ``mod_wsgi-standalone`` will ensure
  that the ``mod_wsgi-httpd`` package is installed first before attempting
  to build and install mod_wsgi. This guarantee is not provided by ``pip``
  if you list ``mod_wsgi-httpd`` and ``mod_wsgi`` packages as two entries.

  The version numbering of the ``mod_wsgi-standalone`` package will follow
  the ``mod_wsgi`` versioning.
