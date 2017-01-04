==============
Version 4.5.13
==============

Version 4.5.13 of mod_wsgi can be obtained from:

  https://codeload.github.com/GrahamDumpleton/mod_wsgi/tar.gz/4.5.13

New Features
------------

* Added ``response-socket-timeout`` option to ``WSGIDaemonProcess``
  directive to allow the timeout on writes back to HTTP client from Apache
  child worker process, when proxying responses from a mod_wsgi daemon
  process, to be separately overridden. Previously this would use the value
  of the Apache ``Timeout`` directive. With this change the timeout will be
  based on ``response-socket-timeout`` option. If that is not set it will
  use the the general ``socket-timeout`` option and if that isn't set only
  then will the value of the Apache ``Timeout`` directive be used.

  The overall purpose of being able to separately control this option is to
  combat against HTTP clients that never read the response, causing the
  response buffer when proxying to fill up, which in turn can cause the
  request thread in the daemon process to block. The default high value of
  the Apache ``Timeout`` directive, at 300 seconds meant it could take a
  while to clear, and if the mod_wsgi daemon processes were configured with
  a low total number of request threads, the whole WSGI application could
  block if this occurred for many requests at the same time.

  When using ``mod_wsgi-express`` the option can be set using the command
  line ``--response-socket-timeout`` option. If using ``mod_wsgi-express``
  the default socket timeout is 60 seconds so the issue would not have had
  as big an impact, especially since ``mod_wsgi-express`` also defines a
  default request timeout of 60 seconds, which would have resulted in the
  daemon process being restarted if the request had blocked in returning
  the response.

  An additional error message is also now logged to indicate that failure
  to proxy the response content was due to a socket timeout. This will help
  to indentify where problems are due to a blocked connection or slow
  client.
