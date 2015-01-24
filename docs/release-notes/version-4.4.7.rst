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
Apache, even though it is a distinct application.

2. Added ``--proxy-url-alias`` option to ``mod_wsgi-express`` for setting
up proxying of a sub URL of the site to a remote URL.

3. Added ``--proxy-virtual-host`` option to ``mod_wsgi-express`` for setting
up proxying of a whole virtual host to a remote URL. Only supports proxying
of HTTP requests and not HTTPS requests.
