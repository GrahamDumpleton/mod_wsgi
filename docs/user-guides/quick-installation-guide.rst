========================
Installation From Source
========================

This page describes installing mod_wsgi on a UNIX-like system from
the original source code using the ``configure`` / ``make`` /
``make install`` build sequence.

For the alternatives:

* To install via ``pip`` from PyPI, see
  :doc:`installation-from-pypi`.
* To install from a Linux distribution package, see
  :doc:`installation-on-linux`.
* For macOS-specific notes, see :doc:`installation-on-macosx`.

Prerequisites
-------------

For the full requirements list (Python and Apache versions, build
toolchain, distribution package names) see :doc:`../requirements`.
In summary you need:

* Python 3.10 or later, with development headers.
* Apache HTTP Server 2.4 with development headers and the ``apxs``
  build tool.
* A C compiler.

If the build fails, see :doc:`installation-issues` for help
diagnosing common problems.

Unpacking the source code
-------------------------

Source tarballs are available from the GitHub release page:

  * https://github.com/GrahamDumpleton/mod_wsgi/releases

After downloading the tarball for the version you want, unpack it::

    tar xvfz mod_wsgi-X.Y.Z.tar.gz

Replace ``X.Y.Z`` with the actual version number.

Configuring the source code
---------------------------

From within the unpacked source directory, run the ``configure``
script::

    ./configure

The configure script identifies the Apache installation to use by
searching standard locations for the Apache build tool ``apxs2`` or
``apxs``, falling back to your ``PATH``. The Python installation to
use is determined by looking for the ``python3`` (or ``python``)
executable in your ``PATH``.

If those are not in standard locations or you want to target
specific alternates, pass ``--with-apxs`` and ``--with-python``::

    ./configure --with-apxs=/usr/local/apache/bin/apxs \
        --with-python=/usr/local/bin/python3

On distributions that ship distinct ``apxs`` builds for different
Apache MPMs (some SUSE and CentOS releases have historically done
this, providing both ``apxs2-worker`` and ``apxs2-prefork`` at the
same time), use ``--with-apxs`` to point at the specific build you
want.

If multiple Python installations are present and the ``configure``
step picks the wrong one, either pass ``--with-python`` to
``configure``, or after install use the ``WSGIPythonHome`` directive
in the Apache configuration to direct the embedded Python
interpreter to the matching Python installation. See
:doc:`../configuration-directives/WSGIPythonHome`.

Building the source code
------------------------

Once configured, build the module::

    make

The only product that needs to be installed is the compiled Apache
module ``mod_wsgi.so``. There are no separate Python files — all
mod_wsgi behaviour is implemented in the C code compiled into the
module. After ``make``, the compiled module can be found in the
``.libs`` subdirectory of the source tree.

To install the module into the standard Apache modules location for
your build, run::

    sudo make install

If you need to place the module in a non-standard location (for
example because your distribution's modules directory differs from
where ``apxs`` installs by default), copy ``.libs/mod_wsgi.so``
manually into place. Keep the file name the same.

Loading the module into Apache
------------------------------

Installing the file does not by itself cause Apache to load it. You
also need to add a ``LoadModule`` directive to the Apache
configuration::

    LoadModule wsgi_module modules/mod_wsgi.so

Place this line in the main Apache configuration file at the same
point that other modules are loaded, or in whichever directory your
distribution uses for module-load configuration (for example
``/etc/apache2/mods-available/`` on Debian-derived distributions or
``/etc/httpd/conf.modules.d/`` on RHEL-derived distributions).

The path argument should be either absolute or relative to the root
of your Apache installation. If you used ``make install`` to install
the package, check where it placed the file to determine the right
value.

Restarting Apache
-----------------

After adding the ``LoadModule`` directive, restart Apache to load
the module. On most modern Linux distributions::

    sudo systemctl restart apache2

or::

    sudo systemctl restart httpd

depending on which name your distribution uses for the Apache
service.

If you are using an unmodified Apache distribution from the Apache
Software Foundation, ``apachectl`` works directly::

    apachectl restart

If a restart misbehaves — most often when upgrading from an older
mod_wsgi version — perform a full stop and then start instead of a
single restart.

If the module loaded successfully, the Apache error log will contain
a line of the form::

    [Sat Jan 01 00:00:00.000000 2026] [wsgi:notice] [pid 12345] mod_wsgi/N.M.K Python/3.X configured

Cleaning up after the build
---------------------------

To clean up build artefacts after install::

    make clean

If you need to rebuild the module against a different Apache
installation, run::

    make distclean

then re-run ``configure`` with the new options before running
``make`` again.
