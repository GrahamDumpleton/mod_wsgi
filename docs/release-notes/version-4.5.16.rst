==============
Version 4.5.16
==============

Version 4.5.16 of mod_wsgi can be obtained from:

  https://codeload.github.com/GrahamDumpleton/mod_wsgi/tar.gz/4.5.16

Bugs Fixed
----------

* The ``WSGIDontWriteBytecode`` option wasn't available when using Python 3.3
  and later. This feature of Python wasn't in initial Python 3 versions, but
  when was later added, mod_wsgi was updated to allow it.

* The feature behind the ``startup-timeout`` option of ``WSGIDaemonProcess``
  was broken by prior fix related to feature in 4.5.10. This meant the option
  was not resulting in daemon processes being restarted when the WSGI script
  file could not be loaded successfully by the specified timeout.

* When using ``WSGIImportScript``, or ``WSGIScriptAlias`` with both the
  ``process-group`` and ``application-group`` options, with the intent of
  preloading a WSGI script file, the ability to reach across to a daemon
  process defined in a different virtual host with same ``ServerName`` was
  always failing and the target daemon process group would be flagged as
  not accessible when instead it should have been.

New Features
------------

* Added ``--allow-override`` option to ``mod_wsgi-express`` to allow use of
  a ``.htaccess`` in document root directory and any directories mapped
  using a URL alias. The argument to the directive should be the directive
  type which can be overridden in the ``.htaccess`` file. The option can be
  used more than once if needing to allow overriding of more than one
  directive type. Argument can be anything allowed by ``AllowOverride``
  directive.
