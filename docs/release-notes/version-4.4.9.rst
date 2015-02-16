=============
Version 4.4.9
=============

Version 4.4.9 of mod_wsgi can be obtained from:

  https://codeload.github.com/GrahamDumpleton/mod_wsgi/tar.gz/4.4.9

For details on the availability of Windows binaries see:

  https://github.com/GrahamDumpleton/mod_wsgi/tree/master/win32

Features Changed
----------------

* The ``--proxy-url-alias`` option of ``mod_wsgi-express`` has been
superseded by the ``--proxy-mount-point`` option. This option now should
only be used to proxy to a whole site or sub site and not individual file
resources. If the mount point URL for what should be proxied doesn't have a
trailing slash, the trailing slash redirection will first be performed on
the proxy for the mount point rather than simply passing it through to
the backend.

New Features
------------

* Added ``--hsts-policy`` option to ``mod_wsgi-express`` to allow a HSTS
(``Strict-Transport-Security``) policy response header to be specified which
should be included when the ``--https-only`` option is used to ensure that
the site only accepts HTTPS connections.
