========
MOD_WSGI
========

The mod_wsgi package is an Apache module that provides a WSGI compliant
interface for hosting Python based web applications on top of the Apache
web server.

Installation of mod_wsgi can now be performed in one of two ways.

The first way of installing mod_wsgi is the traditional way that has
been used in the past, where it is installed as a module direct into your
Apache installation.

The second and newest way of installing mod_wsgi is to install it as a
Python package into your Python installation.

This new way of installing mod_wsgi will compile not only the Apache
module for mod_wsgi, but will also install a set of Python modules and
an admin script for running up Apache directly from the command line
with an auto generated configuration.

This later mechanism for running up Apache with mod_wsgi provides a much
simpler way of getting starting with hosting your Python web application.

In particular, the new installation method makes it very easy to use
Apache/mod_wsgi in a development environment without the need to perform
any Apache configuration yourself.

Installation into Apache
------------------------

For installation directly into your Apache installation, see the full
documentation at:

* http://www.modwsgi.org/

As with either installation method, you must have Apache installed, along
with any developer variant of the Apache package if using binary operating
system packages provided by the operating system.

Installation into Python
------------------------

For installation directly into your Python installation from within this
source directory, you can run::

    python setup.py install

This will compile mod_wsgi and install the resulting module into your
Python installation.

If wishing to install an official release direct from PyPi, you can
instead run::

    pip install mod_wsgi

Note that nothing will be copied into your Apache installation at this
point. As a result, you do not need to run this as the root user unless
installing it into a site wide Python installation rather than a Python
virtual environment.

To verify that the installation was successful, run the command::

    mod_wsgi-express start-server

This will start up Apache/mod_wsgi on port 8000. You can then point your
browser at::

    http://localhost:8000/

to verify the installation worked properly. To stop Apache, use CTRL-C.

For a simple WSGI application contained in a WSGI script file called
``wsgi.py``, in the current directory, you can now run::

    mod_wsgi-express start-server wsgi.py

This instance of the Apache web server will be completely independent of,
and will not interfere with any existing instance of Apache you may have
running on port 80.

If you already have another web server running on port 8000, you can
override the port to be used using the ``--port`` option::

    mod_wsgi-express start-server wsgi.py --port 8001

For a complete list of options you can run::

    mod_wsgi-express start-server --help

Further information on using the new express version of mod_wsgi can be
found in the mod_wsgi documentation.
