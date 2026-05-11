Overview
--------

The mod_wsgi package provides an Apache module that implements a WSGI
compliant interface for hosting Python-based web applications on top of
the Apache web server, conforming to the WSGI specification (PEP 3333).

When installed from PyPi using ``pip``, the ``mod_wsgi`` package builds
the mod_wsgi Apache module against the Apache and Python installations
on your host, and installs the ``mod_wsgi-express`` command-line wrapper
alongside it.

``mod_wsgi-express`` ships a curated Apache configuration template
tuned for hosting a single WSGI application, and generates a complete
Apache configuration from it on the fly based on the command-line
options you supply. Running ``mod_wsgi-express start-server`` brings
up an Apache instance owned by your own user account, with the
generated configuration loading mod_wsgi and wiring in your WSGI
application, without you needing to write or maintain any Apache
configuration yourself. This makes the package an alternative to
using a system-supplied mod_wsgi package together with a hand-managed
Apache configuration, and is well suited to development environments,
container images, and production deployments where having Apache
configured automatically is preferable to managing the Apache
configuration directly.

The ``mod_wsgi`` package can also be used purely as a way to build the
mod_wsgi Apache module (``mod_wsgi.so``) for use with an existing
Apache installation. The built module can be referenced from where
``pip`` placed it, or copied into the modules directory of the target
Apache using the ``mod_wsgi-express install-module`` command. This
works both with the system-supplied Apache on your operating system
and with a self-built Apache installation. In this mode you continue
to write the Apache configuration yourself, and the ``mod_wsgi``
package serves as a convenient way to obtain a compiled Apache module
that matches your Python interpreter.

The ``mod_wsgi`` package on PyPi assumes that you have a suitable
version of Apache pre-installed on your target system, including its
development headers. If you do not, and you are on a UNIX-like system
(Linux), see the companion ``mod_wsgi-standalone`` package on PyPi,
which additionally installs a private build of Apache as part of the
Python installation.

For installation instructions, configuration directives, and usage
guides, see the mod_wsgi documentation site at https://www.modwsgi.org.
