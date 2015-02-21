=============
Version 4.4.9
=============

Version 4.4.9 of mod_wsgi can be obtained from:

  https://codeload.github.com/GrahamDumpleton/mod_wsgi/tar.gz/4.4.9

For details on the availability of Windows binaries see:

  https://github.com/GrahamDumpleton/mod_wsgi/tree/master/win32

Features Changed
----------------

1. The ``--proxy-url-alias`` option of ``mod_wsgi-express`` has been
superseded by the ``--proxy-mount-point`` option. This option now should
only be used to proxy to a whole site or sub site and not individual file
resources. If the mount point URL for what should be proxied doesn't have a
trailing slash, the trailing slash redirection will first be performed on
the proxy for the mount point rather than simply passing it through to
the backend.

2. The signal handler intercept will now be removed automatically from a
Python child process forked from either an Apache child process or a daemon
process. This avoids the requirement of setting ``WSGIRestrictSignal`` to
``Off`` if wanting to setup new signal handlers from a forked child process.

3. The signal handler registrations setup in daemon processes to manage
process shutdown, will now revert to exiting the process when invoked from
a Python process forked from a daemon process. This avoids the need to set
new signal handlers in forked processes to override what was inherited.

Note that this only applies to processes forked from daemon mode processes.
If you are forking processes when your WSGI application is running in
embedded mode, it is still a good idea to set signal handles for ``SIGINT``,
``SIGTERM`` and ``SIGUSR1`` back to ``SIG_DFL`` using ``signal.signal()``
if you want to avoid the possibility of strange behaviour due to the
inherited Apache child worker process signal registrations.

New Features
------------

1. Added ``--hsts-policy`` option to ``mod_wsgi-express`` to allow a HSTS
(``Strict-Transport-Security``) policy response header to be specified which
should be included when the ``--https-only`` option is used to ensure that
the site only accepts HTTPS connections.

2. Added ``WSGITrustedProxyHeaders`` directive. This allows you to specify
a space separated list of inbound HTTP headers used to transfer client
connection information from a proxy to a backend server, that are trusted.
When the specified headers are seen in a request, the values passed via
them will be used to fix up the values in the WSGI ``environ`` dictionary
to reflect client information as was seen by the proxy.

Only the specific headers you are expecting and which is guaranteed to have
only been set by the proxy should be listed. Whether it exists or not, all
other headers in a category will be removed so as to avoid an issue with
a forged header getting through to a WSGI middleware which is looking for a
different header and subsequently overriding whatever the trusted header
specified. This applies to the following as well when more than one
convention is used for the header name.

The header names which are accepted for specifying the HTTP scheme used are
``X-Forwarded-Proto``, ``X-Forwarded-Scheme`` and ``X-Scheme``. It is
expected that the value these supply will be ``http`` or ``https``. When it
is ``https``, the ``wsgi.url_scheme`` value in the WSGI ``environ``
dictionary will be overridden to be ``https``.

Alternate headers accepted are ``X-Forwarded-HTTPS``, ``X-Forwarded-SSL``
and ``X-HTTPS``. If these are passed, the value needs to be ``On``,
``true`` or ``1``. A case insensitive match is performed. When matched, the
``wsgi.url_scheme`` value in the WSGI ``environ`` dictionary will be
overridden to be ``https``.

The header names which are accepted for specifying the target host are
``X-Forwarded-Host`` and ``X-Host``. When found, the value will be used
to override the ``HTTP_HOST`` value in the WSGI ``environ`` dictionary.

The sole header name accepted for specifying the front end proxy server
name is ``X-Fowarded-Server``. When found, the value will be used to
override the ``SERVER_NAME`` value in the WSGI ``environ`` dictionary.

The sole header name accepted for specifying the front end proxy server
port is ``X-Fowarded-Port``. When found, the value will be used to
override the ``SERVER_PORT`` value in the WSGI ``environ`` dictionary.

The header names accepted for specifying the client IP address are
``X-Forwarded-For`` and ``X-Real-IP``. When ``X-Forwarded-For`` is used
then the first IP address listed in the header value will be used. For
``X-Real-IP`` only one IP address should be given. When found, the value
will be used to override the ``REMOTE_ADDR`` value in the WSGI ``environ``
dictionary.

Note that at present there is no facility for specifying a list of trusted
IP addresses to be specified for front end proxies. This will be a feature
added in a future version. When that is available and ``X-Forwarded-For``
is used, then the IP address preceding the furthest away trusted proxy IP
address will instead be used, even if not the first in the list.

The header names accepted for specifying the application mount point are
``X-Script-Name`` and ``X-Forwarded-Script-Name``. When found, the value
will override the ``SCRIPT_NAME`` value in the ``WSGI`` environ dictionary.

When using ``mod_wsgi-express`` the equivalent command line option is
``--trust-proxy-header``. The option can be used multiple times to specify
more than one header.
