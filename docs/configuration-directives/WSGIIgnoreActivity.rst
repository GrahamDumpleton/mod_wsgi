==================
WSGIIgnoreActivity
==================

:Description: Exclude requests from inactivity-timeout activity tracking.
:Syntax: ``WSGIIgnoreActivity On|Off``
:Default: ``WSGIIgnoreActivity Off``
:Context: server config, virtual host, directory, .htaccess
:Override: ``FileInfo``

Controls whether requests in the scope of the directive count as
activity for the purposes of the ``inactivity-timeout`` option to the
WSGIDaemonProcess directive.

mod_wsgi tracks daemon-process activity at three points in the
request path: at the start of overall request handling, when
``wsgi.input.read()`` is called, and each time response data is
written back to the client — whether the WSGI application yields a
chunk from its iterable or calls the legacy ``write()`` callable
returned by ``start_response()``. Each of these resets the
inactivity countdown. With ``WSGIIgnoreActivity On``, those resets
are skipped for matching requests, so the process can still hit the
inactivity threshold and recycle itself even while those requests
are arriving.

The typical use case is excluding low-value traffic such as health
checks or monitoring scrapes that would otherwise keep the
inactivity timer pinned and prevent the daemon from ever being
recycled. For example::

  <Location /health>
  WSGIIgnoreActivity On
  </Location>

This directive only matters when ``inactivity-timeout`` has been
set on the daemon process group. Without that, no idle countdown
is running for activity to be tracked against.

See also the ``inactivity-timeout`` option to the WSGIDaemonProcess
directive.
