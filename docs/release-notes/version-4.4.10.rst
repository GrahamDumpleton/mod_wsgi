==============
Version 4.4.10
==============

Version 4.4.10 of mod_wsgi can be obtained from:

  https://codeload.github.com/GrahamDumpleton/mod_wsgi/tar.gz/4.4.10

For details on the availability of Windows binaries see:

  https://github.com/GrahamDumpleton/mod_wsgi/tree/master/win32

Bugs Fixed
----------

1. Fixed a reference counting bug which would cause a daemon process to
crash if both ``home`` and ``python-path`` options were specified at the
same time with the ``WSGIDaemonProcess`` directive.

2. When using ``--https-only`` option with ``mod_wsgi-express``, the
redirection from the ``http`` address to the ``https`` address was not
setting the correct port for ``https``.

Features Changed
----------------

1. Changed the default Apache log level for ``mod_wsgi-express`` to
``warn`` instead of ``info``. This has been done avoid very noisy logs
when enabling secure HTTP connections. To set back to ``info`` level use
the ``--log-level`` option.

2. When specifying a service script with the ``--service-script`` option of
``mod_wsgi-express``, the home directory for the process will now be set to
the same home directory as used for the hosted WGSI application. Python
modules from the WSGI application will therefore be automatically found
when imported. Any directory paths added using ``--python-path`` option
will also be added as search directories for Python module imports, with
any ``.pth`` files in those directories also being handled. In addition,
the language locale and Python eggs directory used by the hosted WSGI
application will also be used for the service script.

3. When specifying ``--python-path`` option, when paths are now setup for
the WSGI application, they will be added in such a way that they appear at
the head of ``sys.path`` and any ``.pth`` files in those directories are
also handled.

New Features
------------

1. Added the ``--directory-listing`` option to ``mod_wsgi-express`` to
allow automatic directory listings to be enabled when using the static file
application type and no explicit directory index file has been specified.

2. In addition to the convenience function of ``--ssl-certificate`` for
``mod_wsgi-express``, which allowed the SSL certificate and private key
file to be specified using one option by specifying the command file
name up to the extension, separate ``--ssl-certificate-file`` and
``--ssl-certificate-key-file`` options are now also provided. These
would either both need to be specified, or the existing
``--ssl-certificate`` option used, when specifying that secure HTTPS
connections should be used through having specified ``--https-port``.

3. Added the ``--ssl-ca-certificate-file`` option to ``mod_wsgi-express``.
If specified this should give the location of the file with any CA
certificates to be used for client authentication. As soon as this option
is provided, the client authentication will be required for the whole site.
This would generally be used in conjunction with the ``--https-only``
option so that only a secure communication channel is being used.

If you do not wish for the whole site to required client authentication,
you can use the ``--ssl-verify-client`` option to specify sub URLs for
which client authentication should be performed.

4. Added the ``--ssl-environment`` option to ``mod_wsgi-express`` to enable
the passing of standard SSL variables in the WSGI environ dictionary passed
to the WSGI application.

5. Added the ``WSGITrustedProxies`` directive and corresponding option of
``--trust-proxy`` to ``mod_wsgi-express``. This works in conjunction with
the ``WSGITrustedProxyHeaders`` directive and ``--trust-proxy-header``
option of ``mod_wsgi-express``. When trusted proxies are specified, then
proxy headers will only be trusted if the request originated with a trusted
proxy. Further, any IP addresses corresponding to a proxy listed in the
``X-Forwarded-For`` header will only be trusted if specified. When
determining the value for ``REMOTE_ADDR`` the IP preceding the last
recognised proxy the request passed through will be used and not simply the
first IP listed in the header. The header will be rewritten to reflect what
was honoured with client IPs of dubious origin discarded.
