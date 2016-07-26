=======================
Installation On MacOS X
=======================

If you are using MacOS X, mod_wsgi can be compiled from source code
against the standard versions of Python and Apache httpd server supplied
with the operating system. To do this though you will first need to have
installed the Xcode command line tools.

The Xcode command line tools package provides a C compiler, along with
header files and support tools for the Apache httpd server. If you have
already set up your system so as to be able to install additional Python
packages which include C extensions, you likely will already have the
Xcode command line tools.

Install Xcode command line tools
--------------------------------

To install the Xcode command line tools you should run the command::

    xcode-select --install

If this gives you back the error message::

    xcode-select: error: command line tools are already installed, use "Software Update" to install updates

then the tools have already been installed. As noted by the warning
message, do make sure you have run a system software update to ensure
that you have the latest versions of these tools.

If you do not already have the Xcode command line tools installed, running
that ``xcode-select`` command should result in you being prompted to
install them. This may ask you to provide the details of an administrator
account along with the password for that account.

Note that it is not necessary to install the whole of the Xcode
developer application from the MacOS X App Store, only the command line
tools using ``xcode-select``. If you have installed the Xcode developer
application, still ensure that the command line tools are installed and
ensure you have run the system software update.

Configuring and building mod_wsgi
---------------------------------

If you are using the Python and Apache httpd server packages provided with
the operating system, all you need to do to configure the mod_wsgi source
code before building it is to run in the mod_wsgi source code directory::

    ./configure

This should yield output similar to::

    checking for apxs2... no
    checking for apxs... /usr/sbin/apxs
    checking for gcc... gcc
    checking whether the C compiler works... yes
    checking for C compiler default output file name... a.out
    checking for suffix of executables...
    checking whether we are cross compiling... no
    checking for suffix of object files... o
    checking whether we are using the GNU C compiler... yes
    checking whether gcc accepts -g... yes
    checking for gcc option to accept ISO C89... none needed
    checking for prctl... no
    checking Apache version... 2.4.18
    checking for python... /usr/bin/python
    configure: creating ./config.status
    config.status: creating Makefile

The ``configure`` script should show that it has detected ``apxs`` as being
located at ``/usr/sbin/apxs`` and ``python`` as being at ``/usr/bin/python``.

If you get different values for ``apxs`` and ``python`` then it means
that you likely have a separate installation of Python or the Apache
httpd server installed on your system. If this is the case, to ensure that
you use the versions of Python and Apache httpd server provided with the
operating system instead use the command::

    ./configure --with-python=/usr/bin/python --with-apxs=/usr/sbin/apxs

Once you have configured the source code by running ``configure``, you
can build mod_wsgi using the command::

    make

This will compile the mod_wsgi source code and produce a single
``mod_wsgi.so`` file which then needs to be installed into a common
location so that the Apache httpd server can use it.

Installing the mod_wsgi module
------------------------------

What you need to do to install the mod_wsgi module depends on which version
of MacOS X you are using.

For the Apache httpd server provided by the operating system, the directory
``/usr/libexec/apache2`` is used to store the compiled modules. Prior to
MacOS X El Capitan (10.11) this directory was writable and the mod_wsgi
module could be installed here along with all the default modules. With the
introduction of the System Integrity Protection (SIP_) feature in MacOS X
El Capitan this directory is not writable, not even to the root user.

Because of this, if you are using a version of MacOS X prior to MacOS X El
Capitan (10.11) you can use the command::

    sudo make install

to install the mod_wsgi module. As ``sudo`` is being run, you will be
prompted for your password. The module will be installed into the
directory ``/usr/libexec/apache2``. Within the Apache httpd server
configuration file you can then use the standard ``LoadModule`` line
of::

    LoadModule wsgi_module libexec/apache2/mod_wsgi.so

If however you are using MacOS X El Capitan (10.11) or later, the mod_wsgi
module will need to be installed into a different location. If you don't
and try to run just ``sudo make install``, it will fail with the output::

    ./apxs -i -S LIBEXECDIR=/usr/libexec/apache2 -n 'mod_wsgi' src/server/mod_wsgi.la
    /usr/share/httpd/build/instdso.sh SH_LIBTOOL='./libtool' src/server/mod_wsgi.la /usr/libexec/apache2
    ./libtool --mode=install install src/server/mod_wsgi.la /usr/libexec/apache2/
    libtool: install: install src/server/.libs/mod_wsgi.so /usr/libexec/apache2/mod_wsgi.so
    install: /usr/libexec/apache2/mod_wsgi.so: Operation not permitted
    apxs:Error: Command failed with rc=4653056
    .
    make: *** [install] Error 1

The directory you use to install the mod_wsgi module is up to you, but
one suggested option is that you use the directory
``/usr/local/httpd/modules``. Just ensure that this isn't already used
by a separate installation of the Apache httpd server.

To install the mod_wsgi module into this directory use the command::

    sudo make install LIBEXECDIR=/usr/local/httpd/modules

The output from the command will be similar to::

    mkdir -p /usr/local/httpd/modules
    ./apxs -i -S LIBEXECDIR=/usr/local/httpd/modules -n 'mod_wsgi' src/server/mod_wsgi.la
    /usr/share/httpd/build/instdso.sh SH_LIBTOOL='./libtool' src/server/mod_wsgi.la /usr/local/httpd/modules
    ./libtool --mode=install install src/server/mod_wsgi.la /usr/local/httpd/modules/
    libtool: install: install src/server/.libs/mod_wsgi.so /usr/local/httpd/modules/mod_wsgi.so
    libtool: install: install src/server/.libs/mod_wsgi.lai /usr/local/httpd/modules/mod_wsgi.la
    libtool: install: install src/server/.libs/mod_wsgi.a /usr/local/httpd/modules/mod_wsgi.a
    libtool: install: chmod 644 /usr/local/httpd/modules/mod_wsgi.a
    libtool: install: ranlib /usr/local/httpd/modules/mod_wsgi.a
    libtool: install: warning: remember to run `libtool --finish /usr/libexec/apache2'
    chmod 755 /usr/local/httpd/modules/mod_wsgi.so

The warning about needing to run ``libtool --finish`` can be ignored as it
is not required for everything to work.

With the mod_wsgi module installed in this location, the ``LoadModule`` line
in the Apache httpd configuration file should be::

    LoadModule wsgi_module /usr/local/httpd/modules/mod_wsgi.so

Normal steps to then configure the Apache httpd server and mod_wsgi for
your specific WSGI application would then be followed.

.. _SIP: https://en.wikipedia.org/wiki/System_Integrity_Protection
