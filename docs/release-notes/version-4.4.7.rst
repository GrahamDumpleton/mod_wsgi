=============
Version 4.4.7
=============

Version 4.4.7 of mod_wsgi can be obtained from:

  https://codeload.github.com/GrahamDumpleton/mod_wsgi/tar.gz/4.4.7

For details on the availability of Windows binaries see:

  https://github.com/GrahamDumpleton/mod_wsgi/tree/master/win32

Features Changed
----------------

1. The ``proxy-buffer-size`` option to ``WSGIDaemonProcess`` directive
was renamed to ``response-buffer-size`` to avoid confusion with options
related to normal HTTP proxying. The ``--proxy-buffer-size`` option of
``mod_wsgi-express`` was similarly renamed to ``--response-buffer-size``.

New Features
------------

1. Added ``--service-script`` option to ``mod_wsgi-express`` to allow a
Python script to be loaded and executed in the context of a distinct
daemon process. This can be used for executing a service to be managed by
Apache, even though it is a distinct application. The options take two
arguments, a short name for the service and the path to the Python script
for starting the service.

If ``mod_wsgi-express`` is being run as root, then a user and group can be
specified for the service using the ``--service-user`` and
``--service-group`` options. The options take two arguments, a short name
for the service and the user or group name respectively.

2. Added ``--proxy-url-alias`` option to ``mod_wsgi-express`` for setting
up proxying of a sub URL of the site to a remote URL.

3. Added ``--proxy-virtual-host`` option to ``mod_wsgi-express`` for setting
up proxying of a whole virtual host to a remote URL. Only supports proxying
of HTTP requests and not HTTPS requests.

4. Added ``eviction-timeout`` option to ``WSGIDaemonProcess`` directive.
For the case where the graceful restart signal, usually ``SIGUSR1``, is
sent to a daemon process to evict the WSGI application and restart the
process, this controls how many seconds the process will wait, while still
accepting new requests, before it reaches an idle state with no active
requests and shuts down.

The ``graceful-timeout`` option previously performed this exact role in
this case previously, but a separate option is being added to allow a
different timeout period to be specified for the case for forced eviction.
The existing ``graceful-timeout`` option is still used when a maximum
requests option or CPU usage limit is set. For backwards compatibility,
if ``eviction-timeout`` isn't set, it will fall back to using any value
specified using the ``graceful-timeout`` option.

The ``--eviction-timeout`` option has also been added to
``mod_wsgi-express`` and behaves in a similar fashion.

5. Added support for new ``mod_wsgi-httpd`` package. The ``mod_wsgi-httpd``
package is a pip installable package which will build the Apache httpd
server and install it into the Python installation. If the
``mod_wsgi-httpd`` package is installed before installing this package,
then the Apache httpd server installation installed by ``mod_wsgi-httpd``
will be used instead of any system installed version of the Apache httpd
server when running ``mod_wsgi-express``. This allows you to workaround
any inability to upgrade the main Apache installation, or install its 'dev'
package if missing, or install it outright if not present.
