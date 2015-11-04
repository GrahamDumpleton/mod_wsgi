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

2. On Python 3, the IO object wrapped by ``sys.stdout`` and ``sys.stderr``,
according to the Python documentation, must provide a ``fileno()`` method
even though no file descriptor exists corresponding to the Apache error
logs. The method should raise ``IOError`` if called to indicate not file
descriptor can be returned.

Previously, an attempt to use ``fileno()`` on ``sys.stdout`` and ``sys.stderr``
would raise an ``AttributeError`` instead due to there being no ``fileno()``
method.

3. Use compiler include flags from running of ``apr-config`` and
``apu-config`` when doing ``pip`` install of ``mod_wsgi-express``. This is
necessary as on MacOS X 10.11 El Capitan the include flags for APR returned
by ``apxs`` refer to the wrong location causing installation to fail.

New Features
------------

1. When proxying a URL path or a virtual host, now setting request
header for ``X-Forwarded-Port`` so back end knows correct port that
front end used.

2. When proxying a URL path, if the request came in over a secure HTTP
connection, now setting request header for ``X-Forwarded-Scheme`` so back
end knows that front end handled the request over a secure connection.
The value of the header will be ``https``.

3. When using ``mod_wsgi-express``, it is now possible to supply the
``--with-cgi`` option, with any files in the document root directory with
a '.cgi' extension then being processed as traditional CGI scripts.
