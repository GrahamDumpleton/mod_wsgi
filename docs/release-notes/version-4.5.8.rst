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

* Installation on MacOS X Sierra fails for both CMMI and ``pip install``
  methods. This is because Apple removed ``apr-1-config`` and
  ``apu-1-config`` tools needed by ``apxs`` to install third party
  Apache module. A workaround has been incorporated so that installation
  still works when using ``pip install``, but there is no workaround for
  CMMI method. You will need to use ``pip install`` method and then use
  ``mod_wsgi-express module-config`` to get the configuration to then
  add into the Apache configuration so it knows how to load the mod_wsgi
  module. Then configure Apache so it knows about your WSGI application.

* Compilation would fail on MacOS X Sierra as the API was changed for
  obtaining task information. This was used to get memory used by the
  process.

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

* Added the ``--module-config`` option to ``mod_wsgi-express`` to get the
  Apache configuration snippet you would use to load the mod_wsgi module
  from the Python installation direct into Apache, rather than installing
  the module into the Apache modules directory.

* Added experimental support for installing mod_wsgi on Windows using ``pip``.
  Is only tested with Apache 2.4 and Python 3.5. The Apache installation
  must be installed in ``C:\Apache24`` directory. Run ``pip install mod_wsgi``.
  The run ``mod_wsgi-express module-config`` and it will generate the
  required configuration to add into the Apache configuration file to load
  the mod_wsgi module. You still need to separately configure Apache for
  your specific WSGI application.
