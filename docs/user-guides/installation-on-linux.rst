=====================
Installation On Linux
=====================

This page covers installing mod_wsgi on Linux from a distribution
package — using your distribution's package manager to pull in a
pre-built ``mod_wsgi.so`` and the corresponding Apache configuration
glue.

For the alternatives:

* If you want to ``pip install`` mod_wsgi inside a Python virtual
  environment — for example to use ``mod_wsgi-express`` or to keep
  mod_wsgi co-located with your application's Python dependencies
  — see :doc:`installation-from-pypi`.
* If you want to compile mod_wsgi from source and install it into
  Apache the traditional way, see :doc:`quick-installation-guide`.

Choosing a Linux distribution package
-------------------------------------

A distribution package is the right choice if:

* You want mod_wsgi managed by your operating system's package
  manager alongside the rest of your system Apache install.
* You are happy with the version of mod_wsgi that your distribution
  ships.
* You are integrating mod_wsgi into the system Apache rather than
  running a separate ``mod_wsgi-express`` instance.

Distribution packages are convenient and cleanly integrated, but
the version they ship is whatever the distribution chose at release
time. The age and currency of the packaged version varies by
distribution and release; long-term-support releases in particular
can lag upstream by some time. Check the version your distribution
provides; if security currency or access to recent fixes matters
for your deployment, weigh that against installing from PyPI or
from source. See :doc:`../project-status` for the project's overall
version support policy.

Debian and Ubuntu
-----------------

Install the Apache module package alongside Apache itself::

    sudo apt install apache2 libapache2-mod-wsgi-py3

The ``libapache2-mod-wsgi-py3`` package contains the mod_wsgi
module compiled against the Apache and Python that the
distribution ships, plus a configuration snippet that declares the
module to Apache.

Debian-derived distributions split Apache module configuration into
``mods-available`` and ``mods-enabled`` directories. Enable the
wsgi module and restart Apache::

    sudo a2enmod wsgi
    sudo systemctl restart apache2

The configuration snippets that ``a2enmod`` activates live in
``/etc/apache2/mods-available/wsgi.conf`` and
``/etc/apache2/mods-available/wsgi.load``. Add your
application-specific ``WSGIScriptAlias`` and ``WSGIDaemonProcess``
directives in a virtual host file under
``/etc/apache2/sites-available/``, alongside the rest of the
configuration for the site that mod_wsgi is hosting.

RHEL, Fedora, AlmaLinux, Rocky Linux
------------------------------------

Install the Apache module package alongside Apache::

    sudo dnf install httpd python3-mod_wsgi

Module load configuration on RHEL-family distributions lives in
``/etc/httpd/conf.modules.d/``; the ``python3-mod_wsgi`` package
drops a ``10-wsgi-python3.conf`` file there with the appropriate
``LoadModule`` directive. No equivalent of ``a2enmod`` is needed;
the module is loaded as soon as Apache restarts::

    sudo systemctl restart httpd

Application-specific Apache configuration (``WSGIScriptAlias`` and
related directives) belongs in ``/etc/httpd/conf.d/`` or in a
virtual host configuration of your choice.

Software Collections (legacy)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

If you are using the Red Hat Software Collections Library (SCL) —
typically because you need a newer Apache or Python than the base
distribution provides — the package names instead look like::

    sudo dnf install httpd24 httpd24-python3-mod_wsgi

Configuration paths under SCL are scoped under ``/opt/rh/httpd24/``
rather than ``/etc/httpd/``. SCL packaging is becoming less common
as recent RHEL releases ship more current Apache and Python
versions in the base distribution.

Other distributions
-------------------

mod_wsgi is also packaged by Arch (``mod_wsgi``), Alpine
(``apache2-mod-wsgi``, ``apache2-mod-wsgi-python3``), Gentoo
(``www-apache/mod_wsgi``), and a number of others. The general
shape is the same — install the package, ensure Apache is
configured to load the module, restart Apache — but the exact
command names, package names, and configuration directory layout
vary. Consult your distribution's documentation for specifics.

Verifying the install
---------------------

After installing the package and restarting Apache, the Apache
error log should contain a line confirming mod_wsgi loaded::

    [Sat Jan 01 00:00:00.000000 2026] [wsgi:notice] [pid 12345] mod_wsgi/N.M.K Python/3.X configured

Replace ``N.M.K`` with the mod_wsgi version your distribution
shipped, and ``3.X`` with the Python version the package was built
against.

Where to go next
----------------

* :doc:`quick-configuration-guide` — adding ``WSGIScriptAlias`` and
  ``WSGIDaemonProcess`` directives for your application.
* :doc:`configuration-guidelines` — richer configuration examples.
* :doc:`../configuration` — Apache directive reference.
* :doc:`installation-issues` — what to do if Apache does not pick
  up the module after install.
