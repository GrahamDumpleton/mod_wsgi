========================
Quick Installation Guide
========================

This document describes the steps for installing mod_wsgi on a UNIX system
from the original source code.

Apache Requirements
-------------------

Apache 2.0, 2.2 or 2.4 can be used.

For Apache 2.0, 2.2 and 2.4, the single threaded 'prefork' or multithreaded
'worker' Apache MPMs can be used. For Apache 2.4 the 'event' MPM can also
be used.

The version of Apache and its runtime libraries must have be compiled with
support for threading.

On Linux systems, if Apache has been installed from a package repository,
you must have installed the corresponding Apache "dev" package as well.

For most Linux distributions, the "dev" package for Apache 2.X is
"apache2-dev" where the corresponding Apache package was "apache2". Some
systems however distinguish the "dev" package based on which MPM is used by
Apache. As such, it may also be called "apache2-worker-dev" or
"apache2-prefork-dev". If using Apache 2.X, do not mix things up and install
"apache-dev" by mistake, which is the "dev" package for Apache 1.3 called
just "apache".

Python Requirements
-------------------

Any Python 2.X version from Python 2.6 onwards can be used. For Python 3.X,
you will need Python 3.3 or later.

The version of Python being used must have been compiled with support for
threading.

On Linux systems, if Python has been installed from a package repository,
you must have installed the corresponding Python "dev" package as well.

Python should preferably be available as a shared library. If this is not
the case then base runtime memory usage of mod_wsgi will be greater.

Unpacking The Source Code
-------------------------

Source code tar balls can be obtained from:

  * https://github.com/GrahamDumpleton/mod_wsgi/releases

After having downloaded the tar ball for the version you want to use,
unpack it with the command::

    tar xvfz mod_wsgi-X.Y.tar.gz

Replace 'X.Y' with the actual version number for that being used.

Configuring The Source Code
---------------------------

To setup the package ready for building run the "configure" script from
within the source code directory::

    ./configure

The configure script will attempt to identify the Apache installation to
use by searching in various standard locations for the Apache build tools
included with your distribution called "apxs2" or "apxs". If not found in
any of these standard locations, your PATH will be searched.

Which Python installation to use will be determined by looking for the
"python" executable in your PATH.

If these programs are not in a standard location, they cannot be found in
your PATH, or you wish to use alternate versions to those found, the
``--with-apxs`` and ``--with-python`` options can be used in conjunction with
the "configure" script::

    ./configure --with-apxs=/usr/local/apache/bin/apxs \
      --with-python=/usr/local/bin/python

On some Linux distributions, such as SUSE and CentOS, it will be necessary
to use the ``--with-apxs`` option and specify either "/usr/sbin/apxs2-worker"
or "/usr/sbin/apxs2-prefork". This is necessary as the Linux distribtions
allow installation of "dev" packages for both Apache MPM variants at the
same time, whereas other Linux distributions do not.

If you have multiple versions of Python installed and you are not using
that which is the default, you may have to organise that the PATH inherited
by the Apache application when run will result in Apache finding the
alternate version. Alternatively, the WSGIPythonHome directive should
be used to specify the exact location of the Python installation
corresponding to the version of Python compiled against. If this is not
done, the version of Python running within Apache may attempt to use the
Python modules from the wrong version of Python.

Building The Source Code
------------------------

Once the package has been configured, it can be built by running::

    make

If the mod_wsgi source code does not build successfully, see:

  * :doc:`../user-guides/installation-issues`

If successful, the only product of the build process that needs to be
installed is the Apache module itself. There are no separate Python code
files as everything is done within C code compiled into the Apache module.

To install the Apache module into the standard location for Apache modules
as dictated by Apache for your installation, run::

    make install

Installation should be done as the 'root' user or 'sudo' command if
appropriate.

If you want to install the Apache module in a non standard location
dictated by how your operating system distribution structures the
configuration files and modules for Apache, you will need to copy the file
manually into place.

If installing the Apache module by hand, the file is called 'mod_wsgi.so'.
The compiled Apache module can be found in the ".libs" subdirectory. The
name of the file should be kept the same when copied into its appropriate
location.

Loading Module Into Apache
--------------------------

Once the Apache module has been installed into your Apache installation's
module directory, it is still necessary to configure Apache to actually
load the module.

Exactly how this is done and in which of the main Apache configuration
files it should be placed, is dependent on which version of Apache you are
using and may also be influenced by how your operating system's Apache
distribution has organised the Apache configuration files. You may
therefore need to check with any documentation for your operating system to
see in what way the procedure may need to be modified.

In the simplest case, all that is required is to add a line of the form::

    LoadModule wsgi_module modules/mod_wsgi.so

into the main Apache "httpd.conf" configuration file at the same point that
other Apache modules are being loaded. The last option to the directive
should either be an absolute path to where the mod_wsgi module file is
located, or a path expressed relative to the root of your Apache
installation. If you used "make" to install the package, see where it
copied the file to work out what to set this value to.

Restart Apache Web Server
-------------------------

Having adding the required directives you should perform a restart of
Apache to check everything is okay. If you are using an unmodified Apache
distribution from the Apache Software Foundation, a restart is performed
using the 'apachectl' command::

    apachectl restart

If you see any sort of problem, or if you are upgrading from an older
version of mod_wsgi, it is recommended you actually stop and the start
Apache instead::

    apachectl stop
    apachectl start

Note that on many Linux distributions where Apache is prepackaged, the
Apache software has been modified and as a result the 'apachectl' command
may not work properly or the command may not be present. On these systems,
you will need to use whatever is the sanctioned method for restarting
system services.

This may be via an 'init.d' script::

    /etc/init.d/httpd stop
    /etc/init.d/httpd start

or via some special service maintenance script.

On Debian derived distributions, restarting Apache is usually done via the
'invoke-rc.d' command::

    invoke-rc.d apache2 stop
    invoke-rc.d apache2 start

On RedHat derived distributions, restarting Apache is usually done via the
'service' command::

    service httpd stop
    service httpd start

In nearly all cases the scripts used to restart Apache will need to be run
as the 'root' user or via 'sudo'.

In general, for any system where you are using a prepackaged version of
Apache, it is wise to always check the documentation for that package or
system to determine the correct way to restart the Apache service. This is
because they often use a wrapper around 'apachectl', or replace it, with a
script which performs additional actions.

If all is okay, you should see a line of the form::

    Apache/2.4.8 (Unix) mod_wsgi/4.4.21 Python/2.7 configured

in the Apache error log file.

Cleaning Up After Build
-----------------------

To cleanup after installation, run::

    make clean

If you need to build the module for a different version of Apache, you
should run::

    make distclean

and then rerun "configure" against the alternate version of Apache before
attempting to run "make" again.
