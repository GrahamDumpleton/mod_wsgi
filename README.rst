========
MOD_WSGI
========

The mod_wsgi package provides an Apache module that implements a WSGI
compliant interface for hosting Python based web applications on top of the
Apache web server.

Installation of mod_wsgi can now be performed in one of two ways.

The first way of installing mod_wsgi is the traditional way that has
been used in the past, where it is installed as a module directly into your
Apache installation.

The second and newest way of installing mod_wsgi is to install it as a
Python package into your Python installation.

This new way of installing mod_wsgi will compile not only the Apache
module for mod_wsgi, but will also install a set of Python modules and
an admin script for running up Apache directly from the command line
with an auto generated configuration.

This later mechanism for running up Apache, which is referred to as the
mod_wsgi express version, provides a much simpler way of getting starting
with hosting your Python web application.

In particular, the new installation method makes it very easy to use
Apache/mod_wsgi in a development environment without the need to perform
any Apache configuration yourself.

System Requirements
-------------------

With either installation method for mod_wsgi, you obviously must have
Apache installed.

If running Linux, any corresponding developer variant of the specific
Apache package you are using also needs to be installed. This is required
in order to be able to compile mod_wsgi from source code.

For example, on Ubuntu Linux, if you were using the Apache prefork MPM
you would need both:

* apache2-mpm-prefork
* apache2-prefork-dev

If instead you were using the Apache worker MPM, you would need both:

* apache2-mpm-worker
* apache2-threaded-dev

In general it is recommend you use the Apache worker MPM where you have
a choice, although mod_wsgi will work with both, as well as the event
and ITK MPM, plus winnt MPM on Windows.

If you are running MacOS X, the Apache server and required developer
files for compiling mod_wsgi are already present.

Installation into Apache
------------------------

For installation directly into your Apache installation, see the full
documentation at:

* http://www.modwsgi.org/

Also see the documentation if wishing to use mod_wsgi on Windows as the
method of installing direct into your Python installation will not work
on Windows.

Installation into Python
------------------------

To install the mod_wsgi express version directly into your Python
installation, from within the source directory of the mod_wsgi package you
can run::

    python setup.py install

This will compile mod_wsgi and install the resulting package into your
Python installation.

If wishing to install an official release direct from PyPi, you can
instead run::

    pip install mod_wsgi

If you wish to use a version of Apache which is installed into a non
standard location, you can set and export the ``APXS`` environment variable
to the location of the Apache ``apxs`` script for your Apache installation
before performing the installation.

Note that nothing will be copied into your Apache installation at this
point. As a result, you do not need to run this as the root user unless
installing it into a site wide Python installation rather than a Python
virtual environment.

To verify that the installation was successful, run the ``mod_wsgi-express``
script with the ``start-server`` command::

    mod_wsgi-express start-server

This will start up Apache/mod_wsgi on port 8000. You can then verify that
the installation worked by pointing your browser at::

    http://localhost:8000/

When started in this way, the Apache web server will stay in the
foreground. To stop the Apache server, use CTRL-C.

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

Further information on using the mod_wsgi express version see the main
mod_wsgi documentation.

Using mod_wsgi express with Django
----------------------------------

To use the mod_wsgi express version with Django, after having installed
the mod_wsgi package into your Python installation, edit your Django
settings module and add ``mod_wsgi.server`` to the list of installed apps.

::

    INSTALLED_APPS = (
        'django.contrib.admin',
        'django.contrib.auth',
        'django.contrib.contenttypes',
        'django.contrib.sessions',
        'django.contrib.messages',
        'django.contrib.staticfiles',
        'mod_wsgi.server',
    )

To prepare for running of the mod_wsgi express version, ensure that you
first collect up any Django static file assets into the directory specified
for them in the Django settings file::

    python manage.py collectstatic

You can now run the Apache server with mod_wsgi hosting your Django
application by running::

    python manage.py runmodwsgi

If working in a development environment and you would like to have any code
changes automatically reloaded, then you can use the ``--reload-on-changes``
option.

::

    python manage.py runmodwsgi --reload-on-changes

Using mod_wsgi express with New Relic
-------------------------------------

If using `New Relic <http://www.newrelic.com/>`_ for application
performance monitoring, and you already have the ``newrelic`` package
installed and your Python agent configuration file generated, you can use
the ``--with-newrelic`` option.

You do not need to use the ``newrelic-admin`` script that New Relic
provides to wrap the execution of the server. You only need to set the
``NEW_RELIC_CONFIG_FILE`` environment variable to the location of your
agent configuration file.

::

    NEW_RELIC_CONFIG_FILE=`pwd`/newrelic.ini
    export NEW_RELIC_CONFIG_FILE

    mod_wsgi-express wsgi.py --with-newrelic

New Relic provides a free Lite tier so there is no excuse for not using it.
Learn about what your Python web application is really doing. [1]_

Using mod_wsgi express with wdb (Web Debugger)
----------------------------------------------

If a fan of `wdb <https://github.com/Kozea/wdb>`_ for debugging your web
application during development, and you already have that installed, you
can use the ``--with-wdb`` option.

::

    mod_wsgi-express wsgi.py --with-wdb

You do not need to start the wdb server yourself, it will be automatically
started and managed for you.

.. [1] Disclaimer: I work for New Relic and am the primary developer of
       the Python agent. So of course it is awesome. :-)
