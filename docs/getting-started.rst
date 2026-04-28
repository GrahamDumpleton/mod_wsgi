===============
Getting Started
===============

This page walks through getting a minimal "Hello world" WSGI
application running under mod_wsgi end-to-end. The goal is to
validate that mod_wsgi works on your host before you try to drop
a real web framework on top of it.

Start with a "Hello world" application, not a framework. If you
begin with Django, Flask, or Pyramid before you have a basic WSGI
script working, problems with mod_wsgi itself will be hard to
distinguish from problems with the framework or with your
application code.

The recommended path for a first run is ``mod_wsgi-express``,
which gets you to a working Apache + mod_wsgi instance with a
single command. Integrating mod_wsgi into an existing system
Apache install is also fully supported but requires more
configuration; that path is covered separately further down.

Quick start with mod_wsgi-express
---------------------------------

``mod_wsgi-express`` is a Python command-line program installed
when you ``pip install mod_wsgi``. It builds the mod_wsgi module
against the Apache on your host, generates a self-contained Apache
configuration, and starts an Apache instance hosting your WSGI
application — all without touching the system Apache.

Prerequisites
~~~~~~~~~~~~~

Building mod_wsgi from PyPI requires a working compile toolchain on
the host:

* Python 3.10 or later, with development headers (e.g. the
  ``python3-dev`` package on Debian/Ubuntu, ``python3-devel`` on
  RHEL/Fedora).
* Apache HTTP Server 2.4 with development headers and the ``apxs``
  build tool (e.g. ``apache2-dev`` on Debian/Ubuntu,
  ``httpd-devel`` on RHEL/Fedora, ``brew install httpd`` on macOS).
* A C compiler such as ``gcc`` or ``clang`` (on macOS, install the
  Xcode Command Line Tools with ``xcode-select --install``).

If the ``pip install`` step fails, see
:doc:`user-guides/installation-issues` for help diagnosing common
build problems.

Install and run
~~~~~~~~~~~~~~~

It is recommended that you install into a Python virtual environment
to keep the install isolated from your system Python. Either ``uv``
(a fast, modern Python package manager) or Python's built-in
``venv`` module can be used.

Using ``uv``::

    uv venv
    source .venv/bin/activate
    uv pip install mod_wsgi

Using Python's built-in ``venv`` module::

    python3 -m venv .venv
    source .venv/bin/activate
    pip install mod_wsgi

Save the following minimal WSGI application as ``hello.py``::

    def application(environ, start_response):
        start_response('200 OK', [('Content-Type', 'text/plain')])
        return [b'Hello world!\n']

Start ``mod_wsgi-express`` to host it::

    mod_wsgi-express start-server hello.py

By default this listens on port 8000. From another terminal, send
a request to it::

    curl http://localhost:8000/

You should see ``Hello world!`` come back. ``mod_wsgi-express``
runs in the foreground and logs Apache's access and error output
to the terminal; press Ctrl+C to stop it.

What just happened
~~~~~~~~~~~~~~~~~~

The ``mod_wsgi-express`` command launched a real Apache HTTP
Server instance, with the freshly-built mod_wsgi module loaded
into it, configured to serve your ``hello.py`` as a WSGI
application in daemon mode. The Apache configuration was
generated automatically in a private directory and is owned by
your user — there is no system Apache involved and nothing in
``/etc`` was touched.

For the bigger picture of what mod_wsgi and ``mod_wsgi-express``
are doing under the hood, and the deployment shapes available
for production use, see :doc:`how-mod-wsgi-works`.

Integrating with an existing Apache installation
------------------------------------------------

If you already run Apache HTTP Server on the host and want to add
mod_wsgi to it rather than run a separate ``mod_wsgi-express``
instance, the path is:

1. Install mod_wsgi into the system Apache, either from a
   distribution package or from source.
2. Edit Apache's configuration to add ``WSGIScriptAlias`` and
   ``WSGIDaemonProcess`` directives that point at your WSGI
   application.
3. Restart Apache.

For step-by-step instructions see :doc:`installation` and the
:doc:`user-guides/quick-configuration-guide`. For richer
configuration examples and discussion see
:doc:`user-guides/configuration-guidelines`.

Where to go next
----------------

Once you have a Hello world running:

* :doc:`how-mod-wsgi-works` — architectural picture and the
  common deployment patterns.
* :doc:`installation` — installation methods and trade-offs.
* :doc:`user-guides/configuration-guidelines` — richer
  configuration examples.
* :doc:`configuration` — Apache directive reference.
* :doc:`troubleshooting` — what to do when things don't work.
