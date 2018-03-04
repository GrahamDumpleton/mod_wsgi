=============
Version 4.6.0
=============

Version 4.6.0 of mod_wsgi can be obtained from:

  https://codeload.github.com/GrahamDumpleton/mod_wsgi/tar.gz/4.6.0

Bugs Fixed
----------

* Management of reference counting on Python objects in the access,
  authentication, authorization and dispatch hooks wasn't correct for
  certain error cases. The error cases shouldn't have ever occurred, but
  still fixed.

* Point at which details of Python exceptions occuring during access,
  authentication, authorization and dispatch hooks was incorrect and not
  done, with exception cleared, before trying to close per callback error
  log. That the exception hadn't been cleared would result in the call to
  close the per callback error log to itself fail as it believed an
  exception occurred in that call when it hadn't. The result was confusing
  error messages in the Apache error log.

* The deprecated backwards compatability mode enabled by setting the
  directive ``WSGILazyInitialization Off``, to have Python initialised
  in the Apache parent process before forking, was resulting in the Apache
  parent process crashing on Apache shutdown or restart. This resulted in
  Apache child processes and daemon process being orphaned. Issue has been
  fixed, but you should never use this mode and it will be removed in a
  future update. The reason it shouldn't be used is due to memory leaks
  in Python interpreter re-initialisation in same process and also the risks
  due to Python code potentially being run as root.

* When stack traces were being dumped upon request timeout expiring, the
  line numbers of the definition of each function in the stack trace was
  being displayed, instead of the actual line number within the body of the
  function that was executing at the time.

* When stack traces were being dumped upon request timeout expiring, the
  thread ID was being truncated to 32 bits when displayed, meaning it
  wouldn't match the actual Python thread ID on 64 bit systems.

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

  Thanks to Jesús Cea Avión for identifying how using the Apache C API it
  could be identified that the connection had been aborted and in that
  case the original HTTP response code could safely be used.

* When using the Django integration for ``mod_wsgi-express``, if the
  ``whitenoise.middleware.WhiteNoiseMiddleware`` middleware is listed in
  ``MIDDLEWARE`` or ``MIDDLEWARE_CLASSES`` of the Django settings file,
  Apache will now not be used to host Django's static files. This is being
  done to allow WhiteNoise middleware to be used in conjunction with front
  end content delivery networks or other caching systems. If you aren't
  using such a front end and do want Apache to still host the static files,
  either don't list the WhiteNoise middleware in the list of middleware
  classes when using ``mod_wsgi-express``, or pass the ``--url-alias``
  option explictly, along with the URL mount point for static files and the
  directory where they have been placed by the ``collectstatic`` management
  command of Django.

* When running ``mod_wsgi-express`` if the ``TMPDIR`` environment variable
  is specified, it will be used as the directory under which the default
  server root directory for generated files will be created. If ``TMPDIR``
  is not specified, then ``/tmp`` will be used.
  
  This allows ``TMPDIR`` to be used to control the directory used as a
  default. On MacOS where ``TMPDIR`` is set to a unique directory for the
  login session under ``/var/tmp``, this also avoids a problem where a
  system cron job in MacOS will delete files under ``/tmp`` which are older
  than a certain date, which can cause a long running instance of
  ``mod_wsgi-express`` to start failing.

* The "process_stopping" event previously would not be delivered when the
  process was being shutdown and there were still active requests, such as
  when a request timeout occurred. Seen as better to always deliver the
  event if can, even if there were still requests that hadn't been completed.
  This will allow the event handler to dump out details on what the active
  requests were, helping to identify long running or stuck requests.

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

* An explicit error message is now logged when the calculated daemon socket
  path is too long and would be truncated, causing potential failures. A
  shorter directory path should be set with the ``WSGISocketPrefix`` option.

* Added the ``--socket-path`` option to ``mod_wsgi-express`` so you can set
  the daemon socket prefix via the ``WSGISocketPrefix`` directive to an
  alternate directory if the calculated path would be too long based on
  where server root is set for ``mod_wsgi-express``.

* Added the ``--isatty`` option to ``mod_wsgi-express`` to indicate that
  running the command in an interactive terminal session. In this case
  Apache will be run as a sub process rather than it replacing the current
  script. Signals such as SIGINT, SIGTERM, SIGHUP and SIGUSR1 will be
  intercepted and forwarded onto Apache, but the signal SIGWINCH will be
  ignored. This will avoid the problems of Apache shutting down when the
  terminal session Apache is run in is resized.
  
  Technically this could be done automatically by working out if the
  attached terminal is a tty, but is being done using an option at this
  point so the reliability of the mechanism used to run Apache as a sub
  process and the handling of the signals, can be verified. If everything
  checks out, it is likely that this will become the default behaviour
  when the attached terminal is a tty.

* When using ``WSGIDaemonProcess``, if you set the number of threads to zero
  you will enable a special mode intended for using a daemon process to run
  a managed task or program. You will need to use ``WSGIImportScript`` to
  pre-load a Python script into the main application group specified by
  ``%{GLOBAL}`` where the script runs a never ending task, or does an exec
  to run an external program. If the script or external program exits, the
  process is shutdown and replaced with a new one. For the case of using a
  Python script to run a never ending task, a ``SystemExit`` exception will
  be injected when a signal is received to shutdown the process. You can
  use ``signal.signal()`` to register a signal handler for ``SIGTERM`` if
  needing to run special actions before then exiting the process using
  ``sys.exit()``, or to signal your own threads to exit any processing so
  you can shutdown in an orderly manner.

  The ability to do something very similar did previously exist in that
  you could use ``WSGIImportScript`` to run a never ending task even when
  the number of threads was non zero. This was used by ``--service-script``
  option of ``mod_wsgi-express``. The difference in setting ``threads=0``
  is that signals will work correctly and be able to interupt the script.
  Also once the script exits, the process will shutdown, to be replaced,
  where as previously the process would stay running until Apache was
  restart or shutdown. The ``--service-script`` option of ``mod_wsgi-express``
  has been updated to set the number of threads to zero.

* Added ``mod_wsgi.active_requests`` dictionary. This is populated with the
  per request data object for active requests, keyed by the Apache request ID.

* Add ``--cpu-time-limit`` option to ``mod_wsgi-express`` so that limit can
  be imposed on daemon process group as to how much CPU can be used for
  process is restarted automatically.

* Pass a "shutdown_reason" argument with "process_stopping" event so event
  handler knows the reason the process is being shutdown.
