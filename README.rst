Overview
--------

The mod_wsgi package provides an Apache module that implements a WSGI
compliant interface for hosting Python based web applications on top of the
Apache web server.

Installation of mod_wsgi from source code can be performed in one of two
ways.

The first way of installing mod_wsgi is the traditional way that has been
used by many software packages. This is where it is installed as a module
directly into your Apache installation using the commands ``configure``,
``make`` and ``make install``, a method sometimes referred to by the
acyronym CMMI.

The second and newest way of installing mod_wsgi is to install it as a
Python package into your Python installation using the Python ``pip
install`` command.

This newer way of installing mod_wsgi will compile not only the Apache
module for mod_wsgi, but will also install a Python module and admin script
for starting up a standalone instance of Apache directly from the command
line with an auto generated configuration.

This later mechanism for installing mod_wsgi using Python ``pip`` is a much
simpler way of getting starting with hosting your Python web application.
In particular, the new installation method makes it very easy to use
Apache/mod_wsgi in a development environment without the need to perform
any Apache configuration yourself.

The Apache module for mod_wsgi created when using the ``pip install``
method can still be used with the main Apache installation, via manual
configuration if necessary.

On some platforms, this latter method is actually the only option supported
when using the operating system supplied Apache installation. For example,
in MacOS X Sierra, Apple has completely broken the ability to install third
party Apache modules using the ``apxs`` tool normally used for this task.
History suggests that Apple will never fix the problem as they have broken
things in the past in other ways and workarounds were required as they
never fixed those problems either. This time there is no easy workaround as
they no longer supply certain tools which are required to perform the
installation.

System Requirements
-------------------

With either installation method for mod_wsgi, you must have Apache
installed. This must be a complete Apache installation. It is not enough to
have only the runtime packages for Apache installed. You must have the
corresponding development package for Apache installed, which contains the
Apache header files, as these are required to be able compile and install
third party Apache modules.

Similarly with Python, you must have a complete Python installation which
includes the corresponding development package, which contains the header
files for the Python library.

If you are running Debian or Ubuntu Linux with Apache 2.2 system packages,
and were using the Apache prefork MPM you would need both:

* apache2-mpm-prefork
* apache2-prefork-dev

If instead you were using the Apache worker MPM, you would need both:

* apache2-mpm-worker
* apache2-threaded-dev

If you are running Debian or Ubuntu Linux with Apache 2.4 system packages,
regardless of which Apache MPM is being used, you would need both:

* apache2
* apache2-dev

If you are running RHEL, CentOS or Fedora, you would need both:

* httpd
* httpd-devel

If you are using the Software Collections Library (SCL) packages with
RHEL, CentOS or Fedora, you would need:

* httpd24
* httpd24-httpd-devel

If you are running MacOS X, you will need to have the Xcode command line
tools installed. These can be installed by running ``xcode-select --install``.

Installation into Apache
------------------------

For installation directly into your Apache installation using the CMMI
method, see the full documentation at:

* http://www.modwsgi.org/

Alternatively, use the following instructions to install mod_wsgi into your
Python installation and then either copy the mod_wsgi module into your
Apache installation, or configure Apache to use the mod_wsgi module from
the Python installation.

When using this approach, you will still need to manually configure Apache
to have mod_wsgi loaded into Apache, and for it to know about your WSGI
application.

Installation into Python
------------------------

To install the mod_wsgi directly into your Python installation, from within
the source directory of the mod_wsgi package you can run::

    python setup.py install

This will compile mod_wsgi and install the resulting package into your
Python installation.

If wishing to install an official release direct from the Python Package
Index (PyPi), you can instead run::

    pip install mod_wsgi

If you wish to use a version of Apache which is installed into a non
standard location, you can set and export the ``APXS`` environment variable
to the location of the Apache ``apxs`` script for your Apache installation
before performing the installation.

Note that nothing will be copied into your Apache installation at this
point. As a result, you do not need to run this as the root user unless
installing it into a site wide Python installation rather than a Python
virtual environment. It is recommended you always use Python virtual
environments and never install any Python package direct into the system
Python installation.

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

    mod_wsgi-express start-server wsgi.py --port 8080

For a complete list of options you can run::

    mod_wsgi-express start-server --help

For further information related to using ``mod_wsgi-express`` see the main
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
executable will obviously not be found and ``mod_wsgi-express`` will fail
to start at all.

In this case you should work out what the ``httpd`` executable was renamed
to and use the ``--httpd-executable`` option to specify its real location.

For example, if ``httpd`` was renamed to ``apache2``, you might need to use::

    mod_wsgi-express start-server wsgi.py --httpd-executable=/usr/sbin/apache2

In the case of the ``httpd`` executable being replaced with a shell script
which performs additional actions before then executing the original
``httpd`` executable, and the shell script is failing in some way, you will
need to use the location of the original ``httpd`` executable the shell
script is in turn executing.

Running mod_wsgi-express as root
--------------------------------

The primary intention of ``mod_wsgi-express`` is to make it easier for
users to run up Apache on non privileged ports, especially during the
development of a Python web application. If you want to be able to run
Apache using ``mod_wsgi-express`` on a privileged port such as the standard
port 80 used by HTTP servers, then you will need to run
``mod_wsgi-express`` as root. In doing this, you will need to perform
additional steps.

The first thing you must do is supply the ``--user`` and ``--group``
options to say what user and group your Python web application should run
as. Most Linux distributions will pre define a special user for Apache to
run as, so you can use that. Alternatively you can use any other special
user account you have created for running the Python web application::

    mod_wsgi-express start-server wsgi.py --port=80 \
        --user www-data --group www-data

This approach to running ``mod_wsgi-express`` will be fine so long as you
are using a process supervisor which expects the process being run to remain
in the foreground and not daemonize.

If however you are directly integrating into the system init scripts where
separate start and stop commands are expected, with the executing process
expected to be daemonized, then a different process is required to setup
``mod_wsgi-express``.

In this case, instead of simply using the ``start-server`` command to
``mod_wsgi-express`` you should use ``setup-server``::

    mod_wsgi-express setup-server wsgi.py --port=80 \
        --user www-data --group www-data \
        --server-root=/etc/mod_wsgi-express-80

In running this command, it will not actually startup Apache. All it will do
is create the set of configuration files and the startup script to be run.

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
will be cached with the same configuration used each time. If you need to
update the set of options, run ``setup-server`` again with the new set of
options.

Note that even taking all these steps, it is possible that running up
Apache as ``root`` using ``mod_wsgi-express`` may fail on systems where
SELinux extensions are enabled. This is because the SELinux profile may not
match what is being expected for the way that Apache is being started, or
alternatively, the locations that Apache has been specified as being
allowed to access, don't match where the directory specified using the
``--server-root`` directory was placed. You may therefore need to configure
SELinux or move the directory used with ``--server-root`` to an allowed
location.

Using mod_wsgi-express with Django
----------------------------------

To use ``mod_wsgi-express`` with Django, after having installed the
mod_wsgi package into your Python installation, edit your Django settings
module and add ``mod_wsgi.server`` to the list of installed apps.

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

To prepare for running ``mod_wsgi-express``, ensure that you first collect
up any Django static file assets into the directory specified for them in
the Django settings file::

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
 
This will setup all the required files and you can use ``apachectl`` to
start and stop the Apache instance as explained previously.

Connecting into Apache installation
-----------------------------------

If you want to use mod_wsgi in combination with your system Apache
installation, the CMMI method for installing mod_wsgi would normally be
used. If you are on MacOS X Sierra that is no longer possible. Even prior
to MacOS X Sierra, the System Integrity Protection (SIP) system of MacOS X,
prevented installing the mod_wsgi module into the Apache modules
directory.

The CMMI installation method also involves a bit more work as you need to
separately download the mod_wsgi source code, run the ``configure`` tool
and then run ``make`` and ``make install``.

The alternative to using the CMMI installation method is to use the Apache
mod_wsgi module created by running ``pip install``. This can be directly
referenced from the Apache configuration, or copied into the Apache modules
directory.

To use the Apache mod_wsgi module from where ``pip install`` placed it,
run the command ``mod_wsgi-express module-config``. This will output
something like::

    LoadModule wsgi_module /usr/local/lib/python2.7/site-packages/mod_wsgi/server/mod_wsgi-py27.so
    WSGIPythonHome /usr/local/lib

These are the directives needed to configure Apache to load the mod_wsgi
module and tell mod_wsgi where the Python installation directory or virtual
environment was located.

This would be placed in the Apache ``httpd.conf`` file, or if the Linux
distribution separates out module configuration into a ``mods-available``
directory, in the ``wsgi.load`` file within the ``mods-available``
directory. In the latter case where a ``mods-available`` directory is used,
the module would then be enabled by running ``a2enmod wsgi`` as ``root``.
If necessary Apache can then be restarted to verify the module is loading
correctly. You can then configure Apache as necessary for your specific
WSGI application.

Note that because in this scenario the mod_wsgi module for Apache could be
located in a Python virtual environment, if you destroy the Python virtual
environment the module will also be deleted. In that case you would need to
ensure you recreated the Python virtual environment and reinstalled the
mod_wsgi package using ``pip``, or take out the mod_wsgi configuration from
Apache before restarting Apache or it will fail to startup.

Instead of referencing the mod_wsgi module from the Python installation,
you can instead copy the mod_wsgi module into the Apache installation. To
do that, run the ``mod_wsgi-express install-module`` command, running it as
``root`` if necessary. This will output something like::

    LoadModule wsgi_module modules/mod_wsgi-py27.so
    WSGIPythonHome /usr/local/lib

This is similar to above except that the mod_wsgi module was copied to the
Apache modules directory first and the ``LoadModule`` directive references
it from that location. You should take these lines and configure Apache in
the same way as described above. Do note that copying the module like this
will not work on recent versions of MacOS X due to the SIP feature of MacOS X.
