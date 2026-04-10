============
Requirements
============

The mod_wsgi package can be compiled for and used with Apache 2.4 on UNIX
like systems, such as Linux and MacOS X, as well as Windows.

Any of the single threaded 'prefork' or multithreaded 'worker' and 'event'
Apache MPMs can be used when running on UNIX like systems.

Python 3.10 or later is required. The Python installation must have been
installed in a way that shared libraries for Python are provided such that
embedding of Python in another application is possible.

The mod_wsgi package should be able to host any Python web application
which complies with the WSGI_ specification (PEP 3333). The
implementation is very strict with its interpretation of the WSGI
specification. Other WSGI servers available aren't as strict and allow
Python web applications to run which do not comply with the WSGI
specification. If your Python web application doesn't comply properly with
the WSGI specification, then it may fail to run or may run sub optimally
when using mod_wsgi.

.. _WSGI: http://www.python.org/dev/peps/pep-3333/
