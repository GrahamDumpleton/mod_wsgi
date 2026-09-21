=======================
Installation From PyPI
=======================

This page covers installing mod_wsgi from the Python Package Index
(PyPI) using ``pip``. ``pip install`` builds the mod_wsgi Apache
module against the Apache and Python on your host, places the
compiled module inside the installed Python package, and installs
the ``mod_wsgi-express`` admin command alongside it.

When to use this method
-----------------------

Use ``pip install`` if any of the following applies:

* You want the simplest path to running your WSGI application:
  installing the package gives you the ``mod_wsgi-express`` command
  which can host your application without any manual Apache
  configuration.
* You want a mod_wsgi build that lives inside a Python virtual
  environment alongside your application's other dependencies.
* You want a mod_wsgi build for use in a container image.

On Windows, ``pip install`` is the only install path; daemon mode
and ``mod_wsgi-express start-server`` are not available there. See
:doc:`../project-status` for the current Windows support situation.

If instead you want mod_wsgi managed system-wide by your operating
system's package manager, use a Linux distribution package; see
:doc:`installation-on-linux`. If you need a from-source build that
installs into Apache the traditional way (``configure`` / ``make`` /
``make install``), see :doc:`quick-installation-guide`.

Prerequisites
-------------

``pip install mod_wsgi`` compiles native code, so the host must have
the build toolchain in place:

* Python 3.10 or later, with development headers.
* Apache HTTP Server 2.4 with development headers and the ``apxs``
  build tool.
* A C compiler.

See :doc:`../requirements` for the full list and per-distribution
package names. If the build fails, see :doc:`installation-issues`
for help diagnosing common problems.

Installing the package
----------------------

It is recommended that you install into a Python virtual environment
to keep mod_wsgi isolated from your system Python. Either ``uv`` or
Python's built-in ``venv`` module can be used.

Using ``uv``::

    uv venv
    source .venv/bin/activate
    uv pip install mod_wsgi

Using Python's built-in ``venv`` module::

    python3 -m venv .venv
    source .venv/bin/activate
    pip install mod_wsgi

If multiple Apache builds are present on the host (for example
``apxs2-prefork`` and ``apxs2-worker`` on some distributions), or
you want to target a non-default Apache, set the ``APXS``
environment variable before running the install to point at the
desired ``apxs`` script::

    APXS=/usr/sbin/apxs2-event uv pip install mod_wsgi

What you get
------------

A successful install provides three things:

* The ``mod_wsgi.so`` Apache module, compiled and placed inside the
  installed ``mod_wsgi`` Python package directory.
* The ``mod_wsgi-express`` command-line program for starting a
  self-contained Apache plus mod_wsgi instance.
* A ``mod_wsgi.express`` Python module which Django and other
  frameworks can use as an integration point.

Running mod_wsgi-express
------------------------

The fastest way to use the install is to run ``mod_wsgi-express``
directly. It generates an Apache configuration tuned for hosting a
single WSGI application and starts a private Apache instance owned
by your user::

    mod_wsgi-express start-server myapp.wsgi

For a basic walkthrough see :doc:`../getting-started`. For
operational use (privileged ports, Django integration, running
under a process supervisor or in a container) see
:doc:`mod-wsgi-express-quickstart`. For a complete option
reference run ``mod_wsgi-express start-server --help``.

Connecting the pip-built module to system Apache
------------------------------------------------

If you would prefer to use the mod_wsgi module that ``pip`` built
inside an existing system Apache installation, rather than running
a separate ``mod_wsgi-express`` instance, two helper subcommands
make that practical.

Reference the module from where pip put it
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The ``mod_wsgi-express module-config`` command prints the Apache
directives needed to load the module from inside the Python
installation::

    $ mod_wsgi-express module-config
    LoadModule wsgi_module /usr/local/lib/python3.12/site-packages/mod_wsgi/server/mod_wsgi-py312.so
    WSGIPythonHome /usr/local

Place those lines into your Apache configuration. On Debian-derived
distributions a natural location is
``/etc/apache2/mods-available/wsgi.load`` (then enable with
``sudo a2enmod wsgi``); on RHEL-family distributions a natural
location is ``/etc/httpd/conf.modules.d/10-wsgi.conf``; otherwise
they can go directly into ``httpd.conf``.

The ``WSGIPythonHome`` line tells mod_wsgi where the Python
installation that built the module lives, so the embedded Python
interpreter finds the matching standard library. If the install
was inside a virtual environment, ``WSGIPythonHome`` will point at
that virtual environment.

Be aware that with this approach the module file lives inside the
Python installation. If you destroy the virtual environment, the
module file disappears and Apache will fail to start until you
either reinstall mod_wsgi or remove the ``LoadModule`` line.

Copy the module into Apache's modules directory
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Alternatively, ``mod_wsgi-express install-module`` copies the
module into the Apache modules directory and prints the
corresponding ``LoadModule`` line::

    $ sudo mod_wsgi-express install-module
    LoadModule wsgi_module modules/mod_wsgi-py312.so
    WSGIPythonHome /usr/local

Run this with ``sudo`` (or as root); copying into Apache's modules
directory normally requires write permission. Once the file is in
the Apache modules directory it is owned by Apache, so destroying
the Python virtual environment that originally built it no longer
removes the module.

The mod_wsgi-standalone package
-------------------------------

If you want ``pip install`` semantics on a host that has no Apache
installed at all, the separate ``mod_wsgi-standalone`` package on
PyPI bundles a private Apache install of its own::

    pip install mod_wsgi-standalone

The bundled Apache is supplied by a companion ``mod_wsgi-httpd``
package which builds and installs the httpd server inside the
Python environment. You should never need to install
``mod_wsgi-httpd`` yourself: ``mod_wsgi-standalone`` declares it as
a dependency and ``pip`` will pull in a compatible version
automatically.

This is a niche option, intended for environments where adding
Apache as a system package is not practical. It can also be useful
when building Docker images from a base image that does not include
Apache, since installing ``mod_wsgi-standalone`` avoids having to
add a system Apache to the image. Only ``mod_wsgi-express`` is
usable from a ``mod_wsgi-standalone`` install: the bundled Apache
cannot be used to host non-mod_wsgi workloads. ``mod_wsgi-standalone``
follows the same release version numbering as the regular
``mod_wsgi`` package on PyPI.

Listing mod_wsgi-httpd as a separate dependency
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Use ``mod_wsgi-standalone`` in a ``requirements.txt`` file, or in the
dependencies of a ``pyproject.toml`` file. Listing ``mod_wsgi-httpd``
and ``mod_wsgi`` as two separate dependencies does not give the same
result, for two reasons:

* ``mod_wsgi`` is compiled against ``mod_wsgi-httpd``, so
  ``mod_wsgi-httpd`` has to be installed before ``mod_wsgi`` is built.
  When both are named in the one ``pip install`` command, or the one
  requirements file, ``pip`` builds ``mod_wsgi`` first.

* Packaging tools build each package in an isolated environment by
  default, and a package installed in the target environment cannot be
  seen from inside it.

The installation succeeds either way, which makes the problem easy to
miss. If the host has some other Apache installation, ``mod_wsgi`` is
built against that and ``mod_wsgi-httpd`` goes unused. Otherwise the
result can be a ``mod_wsgi-express`` which fails when started.

If you do need to list them separately, and you use `uv
<https://docs.astral.sh/uv/>`_, name ``mod_wsgi-httpd`` as an extra
build dependency of ``mod_wsgi`` in ``pyproject.toml``, using the same
version in both places::

    [project]
    dependencies = [
        "mod_wsgi-httpd==<version>",
        "mod_wsgi",
    ]

    [tool.uv.extra-build-dependencies]
    mod-wsgi = ["mod_wsgi-httpd==<version>"]

With ``pip`` it takes separate commands, the last with build isolation
disabled, which in turn needs ``setuptools`` to be installed already::

    pip install setuptools
    pip install mod_wsgi-httpd
    pip install --no-build-isolation mod_wsgi

This cannot be expressed in a requirements file, as ``pip`` does not
accept the ``--no-build-isolation`` option there.

To check which Apache ``mod_wsgi-express`` is going to run::

    python -c "from mod_wsgi.express import apxs_config; print(apxs_config.HTTPD)"

When ``mod_wsgi-httpd`` is in use, the path printed is inside the
``mod_wsgi_packages/httpd`` directory of the Python environment.

Where to go next
----------------

* :doc:`../getting-started`: quick-start with ``mod_wsgi-express``.
* :doc:`quick-configuration-guide`: manual Apache configuration
  for hosting a WSGI application after wiring the module in.
* :doc:`configuration-guidelines`: richer configuration examples.
* :doc:`../configuration`: Apache directive reference.
