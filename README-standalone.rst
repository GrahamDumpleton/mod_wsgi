Overview
--------

The mod_wsgi package provides an Apache module that implements a WSGI
compliant interface for hosting Python-based web applications on top of the
Apache web server.

The primary package for mod_wsgi is available on the Python package index
(PyPi) as ``mod_wsgi``. That package installs the Apache mod_wsgi module
itself, along with the ``mod_wsgi-express`` command-line wrapper for
starting Apache/httpd with mod_wsgi pre-configured. It assumes that you
have a suitable version of Apache pre-installed on your target system,
and if you don't, installation of the package will fail.

If you are on a UNIX-like system (Linux) and need a version of Apache
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
work on Windows.

When installing mod_wsgi using this method, follow the installation and
usage instructions outlined on the mod_wsgi documentation site at
https://www.modwsgi.org, substituting ``mod_wsgi-standalone`` for
``mod_wsgi`` as the package to install.

The documentation has a page specifically about this package, `The
mod_wsgi-standalone Package
<https://www.modwsgi.org/en/latest/user-guides/mod-wsgi-standalone-package.html>`_.
It covers what the host needs in order to compile everything, how
support for HTTPS depends on the OpenSSL development files being
present when Apache is compiled, how the version of Apache you get is
tied to the version of ``mod_wsgi-standalone`` you install, how
security fixes for Apache reach you, and why ``mod_wsgi-httpd`` and
``mod_wsgi`` should not be listed as two separate dependencies in place
of ``mod_wsgi-standalone``.

**NOTE: Although this package may allow you to install a standalone Apache
version, it is only really recommended that you use this package if you
have absolutely no other choice for getting the Apache httpd server
installed. Always use the Apache httpd server supplied with the operating
system if you can. Building this package if you do choose to do so, will
take some time. So if you think the install is hanging, it is probably
still busy compiling everything.**
