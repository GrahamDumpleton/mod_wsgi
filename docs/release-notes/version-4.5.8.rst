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

* Builds were failing on Windows. Insert appropriate ``#if`` conditional
  around code which shouldn't have been getting included on Windows.

* When ``mod_wsgi-express`` is run as ``root`` and ``--python-eggs``
  option is used, if the directory for the Python eggs didn't exist, it
  was created, but the ownership/group were not set to be the user and
  group that Apache would run the WSGI application. As a result Python
  eggs could not actually be unpacked into the directory. Now change
  the ownership/group of the directory to user/group specified when
  ``mod_wsgi-express`` was run.

New Features
------------

* Add ``WSGIIgnoreActivity`` directive. This can be set to ``On`` inside of
  a ``Location`` directive block for a specific URL path, and any requests
  against matching URLs will not trigger a reset of the inactivity timeout
  for a mod_wsgi daemon process. This can be used on health check URLs so
  that periodic requests against the health check URL do not interfere with
  the inactivity timeout and keep the process running, rather than allowing
  the process to restart due to being otherwise idle.

* Added the ``--ignore-activity`` option to ``mod_wsgi-express``. It will
  set the ``WSGIIgnoreActivity`` directive to ``On`` for the specific URL
  path passed as argument to the option. Any requests against the matching
  URL path will not trigger a reset of the inactivity timeout for a
  mod_wsgi daemon process.
