============
Requirements
============

This page lists the platform, Apache, Python, and build-time
requirements for building and running mod_wsgi. For walk-through
install steps see :doc:`getting-started`; for the broader install
landing page see :doc:`installation`.

Operating system
----------------

mod_wsgi runs on UNIX-like systems and, on a provisional basis, on
Windows.

* **Linux** is the primary, well-tested platform.
* **macOS** is supported using an Apache HTTP Server installed via
  Homebrew. Apple removed the build tooling required to compile
  third-party Apache modules against the system Apache, so the
  Apple-shipped Apache cannot be used; see
  :doc:`user-guides/installation-on-macosx`.
* **Windows** support under the 6.x release line is provisional.
  The project's author does not run Windows and continued Windows
  support depends on community testing and bug reports. Daemon
  mode is not available on Windows; only embedded mode is
  supported. ``mod_wsgi-express start-server`` is also known not
  to work on Windows, so ``pip install mod_wsgi`` is the canonical
  install path on that platform. See :doc:`project-status` for
  details.

Apache HTTP Server
------------------

Apache HTTP Server 2.4 is required. mod_wsgi does not support older
Apache versions.

On UNIX-like systems any of the standard Apache MPMs can be used:

* ``prefork`` — single-threaded, multi-process.
* ``worker`` — multi-threaded, multi-process.
* ``event`` — multi-threaded, multi-process, asynchronous
  connection handling.

On Windows the ``mpm_winnt`` MPM is used.

The Apache build must have been compiled with thread support, even
when only the single-threaded ``prefork`` MPM is in use, because
the daemon processes mod_wsgi creates in daemon mode are themselves
multithreaded by default.

Python
------

Python 3.10 or later is required.

The Python installation must have been built such that an
embeddable shared library is available — for example
``libpython3.X.so`` on Linux, ``Python.framework`` on macOS.
mod_wsgi embeds the Python interpreter into Apache processes,
which is not possible against a static-only Python build.

Most distribution-provided Python packages, Homebrew Python, and
official python.org installers satisfy this requirement out of
the box. Some hand-built Python installations and stripped-down
container-image Pythons do not; building mod_wsgi against such an
installation will fail at the link step.

You can check whether your Python install has a shared library
available with::

    python3 -c 'import sysconfig; print(sysconfig.get_config_var("Py_ENABLE_SHARED"))'

A return value of ``1`` indicates a shared build.

If the build of mod_wsgi fails on the Python side, see
:doc:`user-guides/installation-issues` for help diagnosing the
common causes.

Build toolchain
---------------

mod_wsgi compiles native C code that links against both Apache and
Python. Building it — whether by running ``./configure && make`` on
a source tarball, or by running ``pip install mod_wsgi`` — requires
a working compile toolchain on the host:

* Python development headers (``python3-dev`` on Debian/Ubuntu,
  ``python3-devel`` on RHEL/Fedora; included with Homebrew Python
  on macOS).
* Apache development headers and the ``apxs`` build tool
  (``apache2-dev`` on Debian/Ubuntu, ``httpd-devel`` on
  RHEL/Fedora, ``brew install httpd`` on macOS).
* A C compiler such as ``gcc`` or ``clang`` (on macOS, install
  the Xcode Command Line Tools with ``xcode-select --install``).

If you are installing mod_wsgi from a Linux distribution package
(``libapache2-mod-wsgi-py3`` on Debian/Ubuntu, ``python3-mod_wsgi``
on RHEL/Fedora, or similar) you do not need a build toolchain on
the host; the package ships a pre-compiled module.

WSGI specification compliance
-----------------------------

mod_wsgi can host any Python web application that complies with
the WSGI specification (`PEP 3333`_). The implementation is strict
in its interpretation of the specification. Other WSGI servers may
be more lenient and accept non-conforming applications. If a
Python web application that runs successfully under another WSGI
server fails or behaves oddly under mod_wsgi, the most common
cause is the application not conforming strictly to WSGI.

.. _PEP 3333: https://peps.python.org/pep-3333/
