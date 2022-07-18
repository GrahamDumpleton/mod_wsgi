Overview
--------

The mod_wsgi package provides an Apache module that implements a WSGI
compliant interface for hosting Python based web applications on top of the
Apache web server.

The primary package for mod_wsgi is available on the Python package index
(PyPi) as ``mod_wsgi``. That package assumes that you have a suitable
version of Apache pre-installed on your target system, and if you don't,
installation of the package will fail.

If you are on a UNIX like system (Linux) and need a version of Apache
to be installed for you, you can use the ``mod_wsgi-standalone``
package on PyPi instead. When installing the ``mod_wsgi-standalone``
package it will first trigger the installation of the ``mod_wsgi-httpd``
package, which will result in a version of Apache being installed as
part of your Python installation. Next the ``mod_wsgi`` package will be
installed, with it using the version of Apache installed by the
``mod_wsgi-httpd`` package rather than any system package for Apache.

This method of installation is only suitable for where you want to use
``mod_wsgi-express``. It cannot be used to build mod_wsgi for use with
your system Apache installation. This installation method will not
work on Windows, and also currently fails on macOS because the Apache
Runtime (APR) library, has not been updated to latest macOS versions.

When installing mod_wsgi using this method, except that you will install
the ``mod_wsgi-standalone`` package instead of the ``mod_wsgi`` package,
you should follow installation and usage instructions outlined on the
PyPi page for the ``mod_wsgi`` package.

**NOTE: Although this package may allow you to install a standalone Apache
version, it is only really recommended that you use this package if you
have absolutely no other choice for getting the Apache httpd server
installed. Always use the Apache httpd server supplied with the operating
system if you can. Building this package if you do choose to do so, will
take some time. So if you you think the install is hanging, it is probably
still busy compiling everything.**
