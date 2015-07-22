==============
Version 4.4.14
==============

Version 4.4.14 of mod_wsgi can be obtained from:

  https://codeload.github.com/GrahamDumpleton/mod_wsgi/tar.gz/4.4.14

For details on the availability of Windows binaries see:

  https://github.com/GrahamDumpleton/mod_wsgi/tree/master/win32

Bugs Fixed
----------

1. The ``--compress-responses`` option of ``mod_wsgi-express`` was
failing when Apache 2.4 was used. This was because ``mod_filter`` module
is required when using Apache 2.4 and it wasn't being loaded.

New Features
------------

1. When proxying a URL path or a virtual host, now setting request
header for ``X-Forwarded-Port`` so back end knows correct port that
front end used.

2. When proxying a URL path, if the request came in over a secure HTTP
connection, now setting request header for ``X-Forwarded-Scheme`` so back
end knows that front end handled the request over a secure connection.
The value of the header will be ``https``.
