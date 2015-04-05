========
MOD_WSGI
========

Overview
--------

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

For example, on Ubuntu Linux with Apache 2.2, if you were using the Apache
prefork MPM you would need both:

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

Non standard Apache installations
---------------------------------

Many Linux distributions have a tendency to screw around with the standard
Apache Software Foundation layout for installation of Apache. This can
include renaming the Apache ``httpd`` executable to something else, and in
addition to potentially renaming it, replacing the original binary with a
shell script which performs additional actions which can only be performed
as the ``root`` user.

In the case of the ``httpd`` executable simply being renamed, the
executable will obviously not be found and mod_wsgi express will fail to
start at all.

In this case you should work out what the ``httpd`` executable was renamed
to and use the ``--httpd-executable`` option to specify its real location.

For example, if ``httpd`` was renamed to ``apache2``, you might need to use::

    mod_wsgi-express start-server wsgi.py --httpd-executable=/usr/sbin/apache2

In the case of the ``httpd`` executable being replaced with a shell script
which performs additional actions before then executing the original
``httpd`` executable, and the shell script is failing in some way, you will
need to use the location of the original ``httpd`` executable the shell
script is in turn executing.

Running mod_wsgi express as root
--------------------------------

The primary intention of mod_wsgi express is to make it easier for users
to run up Apache on non privileged ports, especially during the development
of a Python web application. If you want to be able to run Apache using
mod_wsgi express on a privileged port such as the standard port 80 used by
HTTP servers, then you will need to run ``mod_wsgi-express`` as root. In
doing this, you will need to perform additional steps.

The first thing you must do is supply the ``--user`` and ``--group``
options to say what user and group your Python web application should run
as. Most Linux distrbutions will pre define a special user for Apache to
run as, so you can use that. Alternatively you can use any other special
user account you have created for running the Python web application::

    mod_wsgi-express start-server wsgi.py --port=80 \
        --user www-data --group www-data

This approach to running ``mod_wsgi-express`` will be fine so long as you
are using a process supervisor which expects the started process to remain
in the foreground and not daemonize.

If however you are directly integrating into the system init scripts where
separate start and stop commands are expected, with the executing process
expected to be daemonized, then a different process is required to setup
mod_wsgi express.

In this case, instead of simply using the ``start-server`` command to
``mod_wsgi-express`` you should use ``setup-server``::

    mod_wsgi-express setup-server wsgi.py --port=80 \
        --user www-data --group www-data \
        --server-root=/etc/mod_wsgi-express-80

In running this command, it will not actually startup Apache. All it will do
is create the set of configuration files and startup script to be run.

So that these are not created in the default location of a directory under
``/tmp``, you should use the ``--server-root`` option to specify where they
should be placed.

Having created the configuration and startup script, to start the Apache
instance you can now run::

    /etc/mod_wsgi-express-80/apachectl start

To subsequently stop the Apache instance you can run::

    /etc/mod_wsgi-express-80/apachectl stop

You can also restart the Apache instance as necessary using::

    /etc/mod_wsgi-express-80/apachectl restart

Using this approach, the original options you supplied to ``setup-server``
will effectively be cached with the resulting configuration used each time.
If you need to update the set of options, run ``setup-server`` again with
the new set of options.

Note that even taking all these steps, it is possible that running up
Apache as ``root`` using mod_wsgi express may fail on systems where SELinux
extensions are enabled. This is because the SELinux profile may not match
what is being expected for the way that Apache is being started, or
alternatively, the locations that Apache has been specified as being
allowed to access, don't match where the directory specified using the
``--server-root`` directory was placed. You may therefore need to configure
SELinux or move the directory used with ``--server-root`` to an allowed
location.

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

If wanting to have Apache started as root in order to listen on port 80,
instead of using ``mod_wsgi-express setup-server`` as described above,
use the ``--setup-only`` option to the ``runmodwsgi`` management command.

::

    python manage.py runmodwsgi --setup-only --port=80 \
        --user www-data --group www-data \
        --server-root=/etc/mod_wsgi-express-80
    
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

    mod_wsgi-express start-server wsgi.py --with-newrelic
