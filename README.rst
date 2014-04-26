========
MOD_WSGI
========

The mod_wsgi package is an Apache module that provides a WSGI compliant
interface for hosting Python based web applications on top of the Apache
web server.

If you have both Apache and Python installed, including the corresponding
'dev' variants of these packages if on a Linux system, you can install
the mod_wsgi package from PyPi using 'pip'::

    pip install mod_wsgi

This will compile mod_wsgi and install the resulting module into your
Python installation.

Nothing will be copied into your Apache installation at this point. As a
result, you do not need to run this as the root user unless installing it
into a site wide Python installation rather than a Python virtual
environment.

For a simple WSGI application contained in a WSGI script file called
'wsgi.py', in the current directory, you can now run::

    mod_wsgi-admin start-server wsgi.py

This will start up an instance of the Apache web server and mod_wsgi, with
your WSGI application accessible on port 8000. To stop Apache, use CTRL-C.

This instance of the Apache web server will be completely independent of,
and will not interfere with any existing instance of Apache you may have
running on port 80.

If you already have another web server running on port 8000, you can
override the port to be used using the '--port' option::

    mod_wsgi-admin start-server wsgi.py --port 8001

For a complete list of options you can run::

    mod_wsgi-admin start-server --help

For further information on using the 'mod_wsgi-admin' script, you can
access self contained documentation installed with the mod_wsgi package by
using the 'start-server' command without any WSGI script file::

    mod_wsgi-admin start-server

Alternatively, you can view documentation online at:

    http://modwsgi.readthedocs.org

The above instructions refer to the new fast path method for installation
and use of Apache/mod_wsgi. If you wish to use the more traditional way
of installing mod_wsgi into the Apache installation and configure Apache
yourself, then you should refer to the separate online documentation.
