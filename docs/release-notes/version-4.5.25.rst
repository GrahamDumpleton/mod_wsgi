==============
Version 4.5.25
==============

Version 4.5.25 of mod_wsgi can be obtained from:

  https://codeload.github.com/GrahamDumpleton/mod_wsgi/tar.gz/4.5.25

Features Changed
----------------

* Now flagging mod_wsgi package when installing using ``setup.py`` as
  being not ``zip_safe``. This is to workaround an apparent bug with
  ``setuptools`` when using Python 3.7 alpha versions. Believe this will
  disable use of egg file in certain cases.

* When the connection to a client is lost when writing back the response,
  the HTTP response code logged in the Apache access log will be that for
  the original response from the WSGI application rather than a 500 error.

  This is done to avoid confusion where a 500 error is recorded in the
  access log, making you think your WSGI application is at fault when it
  wasn't, but there is no actual error recorded in the error log as to why
  the 500 error was recorded in the access log.
  
  The reason no error is logged in the case of the connection to a client
  being lost is that doing so would create a lot of noise due to the
  regularity which it can happen. The only time an error is logged is when
  a timeout occurs rather than connection being lost. That is done to
  highlight that connections are hanging due to the effect it can have on
  available server capacity when connections are kept open for long times.

New Features
------------

* When using ``--compress-responses`` option of ``mod_wsgi-express``,
  content of type ``application/json`` will now be compressed.

* Added directive ``WSGISocketRotation`` to allow the rotation of the daemon
  socket file path on restarts of Apache to be disabled. By default it is
  ``On`` to preserve existing behaviour but can be set to ``Off`` to have
  the same socket file path always be used for lifetime of that Apache
  instance.

  Rotation should only be disabled where the Apache configuration for the
  mod_wsgi application stays constant over time. The rotation was
  originally done to prevent a request received and handled by an Apache
  worker process being proxied through to a daemon process created under a
  newer configuration. This was done to avoid the possibility of an error,
  or a security issue, due to the old and new configurations being
  incompatible or out of sync.

  By setting rotation to ``Off``, when a graceful restart is done and the
  Apache worker process survives for a period of time due to keep alive
  connections, those subsequent requests on the keep alive connection will
  now be proxied to the newer daemon processes rather than being failed as
  occurred before due to no instances of daemon process existing under the
  older configuration.

  Although socket rotation still defaults to ``On`` for mod_wsgi, this is
  overridden for ``mod_wsgi-express`` where it is always now set to ``Off``.
  This is okay as is not possible for configuration to change when using it.

* The ``process-group`` and ``application-group`` options can now be used
  with the ``WSGIScriptAliasMatch`` directive. If substitutions are not used
  in the value for the WSGI script file target path, then the WSGI script
  file will be pre-loaded if both ``process-group`` and ``application-group``
  options are used at the same time.

  Note that the documentation was wrongly updated recently to suggest that
  these options were already supported by ``WSGIScriptAliaMatch``. This was
  done in error. Instead of removing the documentation, the ability to use
  the options with the directive was instead added with this release.

* Raise an actual exception when installing using ``pip`` or using the
  ``setup.py`` file on MacOS and it doesn't appear that Xcode application
  has been installed. Lack of Xcode application will mean that cannot find
  the SDK which has the Apache include files.
