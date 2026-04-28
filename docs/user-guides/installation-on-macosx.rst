=====================
Installation On macOS
=====================

This page covers installing mod_wsgi on macOS.

Installation against the Apple-supplied Apache ``httpd`` server is
no longer supported. Apple removed the Apache build tools (notably
the ``apxs`` script and matching configuration) from macOS some
years ago, and there is no supported way to compile third-party
Apache modules against the system Apache. The recommended path is
to install Apache yourself via Homebrew and build mod_wsgi against
that.

Prerequisites
-------------

Install the build prerequisites via Homebrew and the Xcode Command
Line Tools::

    xcode-select --install
    brew install httpd
    brew install python

The Xcode Command Line Tools provide the C compiler. ``brew install
httpd`` provides Apache 2.4, its development headers, and the
``apxs`` build tool. ``brew install python`` provides a Python
installation suitable for embedding; skip this step if you already
have a satisfactory Python installation from another source — a
python.org installer, ``pyenv``, or ``uv``-managed Python all work.

Homebrew installs to a different prefix depending on host
architecture:

* On Apple Silicon (arm64) Macs, the Homebrew prefix is
  ``/opt/homebrew``.
* On Intel (x86_64) Macs, the Homebrew prefix is ``/usr/local``.

In both cases ``brew install httpd`` places ``apxs`` at
``$(brew --prefix)/bin/apxs`` and the Apache configuration under
``$(brew --prefix)/etc/httpd/``.

Installing mod_wsgi
-------------------

Once the prerequisites are in place, install mod_wsgi using one of
two methods.

Install from PyPI
~~~~~~~~~~~~~~~~~

The simplest path is ``pip install mod_wsgi``, which builds the
mod_wsgi module against the Homebrew Apache and also installs the
``mod_wsgi-express`` admin command::

    python3 -m venv .venv
    source .venv/bin/activate
    pip install mod_wsgi

If Homebrew's ``apxs`` is not the first ``apxs`` on your ``PATH``
(unusual, but possible if you have multiple Apache installs), set
the ``APXS`` environment variable explicitly::

    APXS=$(brew --prefix)/bin/apxs pip install mod_wsgi

For the full pip-install workflow, including how to wire the
resulting module into the Homebrew Apache configuration so it can
host an application directly rather than via ``mod_wsgi-express``,
see :doc:`installation-from-pypi`.

Build from source
~~~~~~~~~~~~~~~~~

Alternatively, build mod_wsgi from a source tarball against the
Homebrew Apache::

    ./configure --with-apxs=$(brew --prefix)/bin/apxs
    make
    sudo make install

Then add a ``LoadModule wsgi_module`` directive to the Homebrew
Apache configuration at ``$(brew --prefix)/etc/httpd/httpd.conf``.
See :doc:`quick-installation-guide` for the full source-build
workflow.

Running the Homebrew Apache
---------------------------

The Homebrew Apache runs entirely separately from anything Apple
might still ship. Start and stop it via ``brew services``::

    brew services start httpd
    brew services stop httpd

By default the Homebrew Apache listens on port 8080, not port 80.
If you want it to listen on 80, edit
``$(brew --prefix)/etc/httpd/httpd.conf`` and change the ``Listen``
directive. Binding to port 80 requires Apache to be started with
sufficient privilege; the simplest path is ``sudo brew services
start httpd``.

Where to go next
----------------

* :doc:`../getting-started` — quick-start with ``mod_wsgi-express``.
* :doc:`installation-from-pypi` — the full pip-install workflow.
* :doc:`quick-installation-guide` — the full from-source workflow.
* :doc:`quick-configuration-guide` — adding ``WSGIScriptAlias``
  directives for your application.
* :doc:`installation-issues` — what to do if the build fails.
