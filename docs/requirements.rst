============
Requirements
============

The mod_wsgi package can be compiled for and used with most recent patch
revisions of Apache 2.0, 2.2 or 2.4 on UNIX like systems, such as Linux and
MacOS X, as well as Windows.

It is highly recommended that you use Apache 2.4. Older versions of Apache
have architectural design problems and sub optimal configuration defaults,
that can result in excessive memory usage in certain circumstances. More
recent mod_wsgi versions attempt to protect against these problems in
Apache 2.0 and 2.2, however it is still better to use Apache 2.4.

Any of the single threaded 'prefork' or multithreaded 'worker' and 'event'
Apache MPMs can be used when running on UNIX like systems.

Both Python 2 and 3 are supported. The minimum recommended versions of each
being Python 2.6 and 3.3 respectively. The Python installation must have
been installed in a way that shared libraries for Python are provided such
that embedding of Python in another application is possible.

The mod_wsgi package should be able to host any Python web application
which complies with the WSGI_ specification (PEP 3333). The
implementation is very strict with its interpretation of the WSGI
specification. Other WSGI servers available aren't as strict and allow
Python web applications to run which do not comply with the WSGI
specification. If your Python web application doesn't comply properly with
the WSGI specification, then it may fail to run or may run sub optimally
when using mod_wsgi.

.. _WSGI: http://www.python.org/dev/peps/pep-3333/
