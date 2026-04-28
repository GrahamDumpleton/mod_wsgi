=======================
Installation On Windows
=======================

This page covers installing mod_wsgi on Windows.

Windows status
--------------

Windows support under the 6.x release line is provisional. The
project's author does not run Windows; continued Windows support
depends on community testing and bug reports. See
:doc:`../project-status` for details.

Several things that work on UNIX-like systems are not available on
Windows:

* Daemon mode of mod_wsgi is not available. WSGI applications run
  in embedded mode only.
* The ``mod_wsgi-express start-server`` command does not work on
  Windows. ``pip install mod_wsgi`` itself works, and the resulting
  module can be loaded into a system Apache via manual
  configuration.
* The ``configure`` / ``make`` / ``make install`` source build flow
  is not supported on Windows; the required build tooling is not
  part of the Windows Apache distributions. Use ``pip install``
  instead.

Apache HTTP Server
------------------

For Windows it is recommended that you use the Apache distribution
from Apache Lounge:

  * https://www.apachelounge.com

Apache distributions other than Apache Lounge are sometimes
incomplete — in particular missing the development files (the
``include`` directory and the build glue equivalent to ``apxs``)
that are needed to compile third-party Apache modules. Apache
Lounge supplies a complete distribution suitable for building
mod_wsgi against.

By default, the Windows mod_wsgi build expects Apache to be
installed under ``C:/Apache24``. If your Apache is installed
elsewhere, set the ``MOD_WSGI_APACHE_ROOTDIR`` environment variable
to the directory containing the Apache distribution before running
``pip install``. Use forward slashes in the path, and avoid path
components that contain spaces::

    set MOD_WSGI_APACHE_ROOTDIR=C:/Programs/Apache24

Python
------

Use a standard Python installation — for example a python.org
installer, ``uv``-managed Python, or ``conda``-managed Python.
Python 3.10 or later is required. The Python installation must
include the standard development headers and import library so
that mod_wsgi can link against it.

C compiler
----------

``pip install mod_wsgi`` compiles native C code, so the host needs
a Microsoft Visual C++ build environment compatible with the
Python in use. The simplest way to provide this is to install the
free *Build Tools for Visual Studio* — selecting the "Desktop
development with C++" workload — from Microsoft's downloads page.

Installing mod_wsgi
-------------------

With Apache, Python, and the C build tools in place, install
mod_wsgi from PyPI::

    python -m venv .venv
    .venv\Scripts\activate
    pip install mod_wsgi

The install builds the mod_wsgi Apache module against the Apache
identified by either ``C:/Apache24`` or
``MOD_WSGI_APACHE_ROOTDIR``, and against the Python in use.

Loading the module into Apache
------------------------------

After ``pip install``, run ``mod_wsgi-express module-config`` to
print the directives needed to load the module into Apache::

    mod_wsgi-express module-config

Add the printed ``LoadModule`` and ``WSGIPythonHome`` directives to
your Apache ``httpd.conf`` file at the same point that other
modules are loaded.

Application-specific Apache configuration — for example a
``WSGIScriptAlias`` directive mapping a URL to a WSGI script — is
added to ``httpd.conf`` in the same way as on UNIX. See
:doc:`quick-configuration-guide`.

Restart Apache (via the Apache Lounge service entry, or whichever
mechanism your Apache distribution uses) for the changes to take
effect.

Where to go next
----------------

* :doc:`installation-from-pypi` — non-Windows-specific aspects of
  the pip-install workflow, including the ``module-config`` and
  ``install-module`` subcommands.
* :doc:`quick-configuration-guide` — adding ``WSGIScriptAlias``
  directives for your application.
* :doc:`../configuration` — Apache directive reference.
* :doc:`../project-status` — current Windows support status.
