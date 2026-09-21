===============================
The mod_wsgi-standalone Package
===============================

This page covers the ``mod_wsgi-standalone`` package on PyPI, which
installs a private build of the Apache HTTP Server into your Python
environment for ``mod_wsgi-express`` to run, and the companion
``mod_wsgi-httpd`` package which supplies that Apache. For the
regular ``mod_wsgi`` package, which is built against an Apache
already on the host, see :doc:`installation-from-pypi`.

How the packages relate
-----------------------

Three package names are involved:

``mod_wsgi``
    The mod_wsgi Apache module and the ``mod_wsgi-express`` command,
    compiled against an Apache installation which is already on the
    host.

``mod_wsgi-httpd``
    A build of the Apache HTTP Server, along with the APR, APR-util
    and PCRE2 libraries it needs, compiled from source and installed
    inside the Python environment. It contains no mod_wsgi code.

``mod_wsgi-standalone``
    The same source code as ``mod_wsgi``, released at the same time
    under the same version number. The one difference is that it
    declares a dependency on ``mod_wsgi-httpd``, so that the module
    is compiled against that Apache and ``mod_wsgi-express`` runs
    that Apache, in place of one supplied by the operating system.

You install ``mod_wsgi-standalone``. You should not need to install
``mod_wsgi-httpd`` yourself, as ``pip`` installs the required version
of it automatically::

    pip install mod_wsgi-standalone

Do not install both ``mod_wsgi`` and ``mod_wsgi-standalone`` into the
same Python environment. They provide the same Python package and
the same ``mod_wsgi-express`` command.

When to use it
--------------

This is a niche option, intended for environments where adding Apache
as a system package is not practical: a host where you cannot install
system packages, a base container image that has Python but no
Apache, or a distribution whose Apache is too old. Always use the
Apache supplied with the operating system if you can.

The reason for that advice is how security fixes reach you. With the
Apache from your operating system, the vendor ships fixes for Apache,
APR and the libraries they use, and they arrive through the normal
system update process. With ``mod_wsgi-standalone``, a fix arrives
only after a new ``mod_wsgi-httpd`` has been released for the fixed
Apache version, a new ``mod_wsgi-standalone`` has been released which
requires it, and you have upgraded and redeployed. Nothing updates it
for you.

Only ``mod_wsgi-express`` is usable from a ``mod_wsgi-standalone``
install. It cannot be used to build mod_wsgi for a system Apache, and
the bundled Apache is not intended for hosting anything other than
what ``mod_wsgi-express`` configures it for.

Linux and macOS are supported. Windows is not.

What the host needs
-------------------

Everything is compiled on the host at install time, so the build
toolchain must be in place first:

* A C compiler and ``make``.

* Python 3.10 or later, with development headers.

* The development files for the expat XML parser, which APR-util
  requires: ``libexpat1-dev`` on Debian and Ubuntu, ``expat-devel``
  on RHEL, Fedora, AlmaLinux and Rocky.

* The development files for OpenSSL, if you need HTTPS. See
  :ref:`standalone-https-support` below.

The source code for Apache, APR, APR-util and PCRE2 is carried inside
the ``mod_wsgi-httpd`` package on PyPI, so nothing beyond the package
itself has to be downloaded during the install.

Compiling Apache takes several minutes, and ``pip`` shows no progress
while it happens. If the install appears to have hung, it is probably
still busy compiling. Use ``pip install -v`` to watch the build.

.. _standalone-https-support:

HTTPS support
-------------

The HTTPS options of ``mod_wsgi-express`` rely on the Apache
``mod_ssl`` module. When ``mod_wsgi-httpd`` is compiled, ``mod_ssl``
is built only if the OpenSSL development files are found on the host.
If they are not found, it is left out without any error, and the
install still succeeds.

To have ``mod_ssl`` available, install the OpenSSL development files
before installing ``mod_wsgi-standalone``: ``libssl-dev`` on Debian
and Ubuntu, ``openssl-devel`` on RHEL, Fedora, AlmaLinux and Rocky.
Slim container images normally do not include them. On macOS, the
OpenSSL installed by Homebrew is not in a location which is searched
by default, so ``mod_ssl`` is normally not built there.

To check whether ``mod_ssl`` was built, look for it in the modules
directory of the bundled Apache::

    python -c "from mod_wsgi.express import apxs_config; print(apxs_config.LIBEXECDIR)"

If ``mod_ssl.so`` is not in the directory printed, Apache will fail to
start when ``mod_wsgi-express`` is given any of its HTTPS options. If
the OpenSSL development files were added after ``mod_wsgi-httpd`` was
installed, it has to be compiled again for ``mod_ssl`` to appear::

    pip install --force-reinstall --no-cache-dir mod_wsgi-httpd==<version>

See :doc:`enabling-https` for the HTTPS options themselves.

Versions and upgrades
---------------------

``mod_wsgi-standalone`` follows the same version numbering as
``mod_wsgi``, and the two are released together.

The version of ``mod_wsgi-httpd`` is the version of the Apache HTTP
Server it builds, followed by one further number. Version
``2.4.68.2`` builds Apache 2.4.68. The final number starts at ``1``
for each Apache version and goes up when the package is released
again for the same Apache version, for example to move to a newer
APR, APR-util or PCRE2.

Each release of ``mod_wsgi-standalone`` requires one exact version of
``mod_wsgi-httpd``. The Apache version you get is therefore decided
by which release of ``mod_wsgi-standalone`` you install, and not by
when you install it. To move to a newer Apache, upgrade
``mod_wsgi-standalone`` to a release which requires it. The
:doc:`../release-notes` for a version say when the required
``mod_wsgi-httpd`` version changed.

To see what is installed::

    pip show mod_wsgi-standalone mod_wsgi-httpd

To check which Apache ``mod_wsgi-express`` is going to run::

    python -c "from mod_wsgi.express import apxs_config; print(apxs_config.HTTPD)"

When ``mod_wsgi-httpd`` is in use, the path printed is inside the
``mod_wsgi_packages/httpd`` directory of the Python environment.

Listing mod_wsgi-httpd as a separate dependency
-----------------------------------------------

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

Afterwards, use the command given under `Versions and upgrades`_ to
check that ``mod_wsgi-express`` is going to run the Apache from
``mod_wsgi-httpd``.

Where to go next
----------------

* :doc:`installation-from-pypi`: the regular ``mod_wsgi`` package,
  and what is common to both packages once installed.
* :doc:`mod-wsgi-express-quickstart`: running ``mod_wsgi-express``.
* :doc:`installing-with-docker`: a container image built with
  ``mod_wsgi-standalone``.
