====================
Virtual Environments
====================

This page covers using Python virtual environments with mod_wsgi.

A Python virtual environment is a self-contained directory holding a
specific Python interpreter plus its own set of installed packages.
Using one keeps the dependencies of a WSGI application isolated from
the system Python and from other applications on the same host. It
is strongly recommended that you always run a WSGI application out
of a virtual environment rather than against the system Python.

A virtual environment is required when:

* Multiple WSGI applications hosted by the same Apache need
  different versions of the same package.
* Distinct mod_wsgi daemon process groups host WSGI applications
  for different users, and each user needs to manage their own
  packages.

Either ``python -m venv`` (Python's built-in virtual-environment
support) or ``uv venv`` (a fast modern alternative from the ``uv``
package manager) is suitable for creating the environment. The
older ``virtualenv`` package also still works and you may still
encounter it; ``virtualenvwrapper`` is no longer actively maintained
but similarly works if you already use it.

How you point mod_wsgi at the virtual environment depends on the
deployment shape — daemon vs. embedded mode, single vs. multiple
WSGI applications. The common scenarios are covered below.

Location of the Virtual Environment
-----------------------------------

Before configuring mod_wsgi, find out the on-disk path of your
virtual environment. Activate it from a shell and run::

    python -c 'import sys; print(sys.prefix)'

This prints the path you will use when pointing mod_wsgi at it. The
examples on this page assume virtual environments are stored under
``/usr/local/venvs``, so a specific environment might be at::

    /usr/local/venvs/example

This must be the *root* directory of the virtual environment — the
one containing ``bin/`` and ``lib/`` — not the path to the
``python`` executable inside it. Pointing mod_wsgi at
``/usr/local/venvs/example/bin/python`` will not work.

The user Apache runs your code as must be able to read the virtual
environment's files. On some Linux distributions a user's home
directory is not accessible to other users, so consider locating
WSGI application code and the virtual environment somewhere outside
``/home/<user>/`` rather than relaxing the home directory's
permissions.

Virtual Environment and Python Version
--------------------------------------

The virtual environment used with mod_wsgi must have been created
from the same Python installation that mod_wsgi was built against.
A virtual environment cannot be used to make mod_wsgi use a
different Python version, or even a different installation of the
same version.

For example, you cannot make a mod_wsgi built for Python 3.10 use a
virtual environment created from Python 3.12. The Python library
mod_wsgi links against is baked into ``mod_wsgi.so`` at build time.
mod_wsgi embeds Python directly; it does not run a ``python``
command-line program, so the choice of Python is fixed when
mod_wsgi is built.

Even when the Python version matches, two installations of the same
version may have been compiled with different options and the
resulting ABIs can differ in subtle ways. Mixing them is not safe.

If you need to switch Python version or installation, rebuild
mod_wsgi against the new Python.

Daemon Mode (Single Application)
--------------------------------

The preferred way to set up mod_wsgi is to run each WSGI application
in its own daemon process group. A typical configuration is::

    WSGIDaemonProcess myapp

    WSGIProcessGroup myapp
    WSGIApplicationGroup %{GLOBAL}

    WSGIScriptAlias / /some/path/project/myapp.wsgi

    <Directory /some/path/project>
        Require all granted
    </Directory>

``WSGIDaemonProcess`` defines the daemon process group;
``WSGIProcessGroup`` selects it for this application. Because only
one application runs in this daemon process group,
``WSGIApplicationGroup %{GLOBAL}`` forces it into the main Python
interpreter context of each daemon process, which avoids issues
with C extension modules that don't tolerate running in Python
sub-interpreters.

To use a virtual environment, add the ``python-home`` option to
``WSGIDaemonProcess``::

    WSGIDaemonProcess myapp python-home=/usr/local/venvs/myapp

All Python packages the application needs are then installed into
that virtual environment.

Daemon Mode (Multiple Applications)
-----------------------------------

If multiple WSGI applications run in a single daemon process group
(rather than each having its own — the recommended setup), the
configuration looks something like::

    WSGIDaemonProcess myapps

    WSGIProcessGroup myapps

    WSGIScriptAlias /myapp3 /some/path/project/myapp3.wsgi
    WSGIScriptAlias /myapp2 /some/path/project/myapp2.wsgi
    WSGIScriptAlias / /some/path/project/myapp1.wsgi

    <Directory /some/path/project>
        Require all granted
    </Directory>

Or, if mounting the directory directly::

    WSGIDaemonProcess myapps

    WSGIProcessGroup myapps

    WSGIScriptAlias / /some/path/project/

    <Directory /some/path/project>
        Require all granted
    </Directory>

``WSGIApplicationGroup`` is deliberately omitted. Without it, each
WSGI application runs in its own Python sub-interpreter context
inside the daemon process. Many WSGI frameworks — Django is the
canonical example — do not support multiple instances of an
application running in the same Python interpreter context
concurrently, so per-application sub-interpreters are necessary.

If all applications can share a single virtual environment, use
``python-home`` exactly as in the single-application case::

    WSGIDaemonProcess myapps python-home=/usr/local/venvs/myapps

Because the environment is shared, all applications must agree on
the version of any given package.

If each application needs its own virtual environment,
``python-home`` alone is not enough — only one ``python-home`` value
is allowed per daemon process group. In that case, activate the
per-application virtual environment from inside the WSGI script
itself.

If your virtual environment was created with ``uv venv`` or with
``virtualenv``, it includes an ``activate_this.py`` script that
performs a complete activation: it adds the virtual environment's
``site-packages`` to the front of ``sys.path``, sets ``sys.prefix``
to the virtual environment root, and sets ``VIRTUAL_ENV`` in the
process environment. At the top of the WSGI script, before any
other imports::

    python_home = '/usr/local/venvs/myapp1'

    activate_this = python_home + '/bin/activate_this.py'
    exec(open(activate_this).read(), dict(__file__=activate_this))

Set ``python_home`` differently for each application's WSGI script.

If your virtual environment was created with ``python -m venv``,
no ``activate_this.py`` script is provided and you must add the
``site-packages`` directory to ``sys.path`` manually::

    python_home = '/usr/local/venvs/myapp1'

    import sys
    import site

    python_version = '.'.join(map(str, sys.version_info[:2]))
    site_packages = python_home + '/lib/python%s/site-packages' % python_version
    site.addsitedir(site_packages)

Whichever activation method is used, the underlying Python
installation remains in view — anything installed against it is
still importable from the WSGI application. This can lead to
surprises: a missing entry in your ``requirements.txt`` may not
produce an ``ImportError`` if the package happens to be installed
against the underlying Python.

To prevent this, still set ``python-home`` on ``WSGIDaemonProcess``
but point it at an *empty* virtual environment which has no packages
installed::

    WSGIDaemonProcess myapps python-home=/usr/local/venvs/empty

This makes the underlying Python that empty virtual environment
rather than your system Python, so per-application activations
cleanly override it.

For the manual ``site.addsitedir()`` path the empty-environment
trick is also needed for ``sys.path`` ordering: ``site.addsitedir()``
adds entries to the *end* of ``sys.path``, so anything installed
into the ``python-home`` virtual environment would otherwise take
precedence over the per-application virtual environment. Keeping
the ``python-home`` virtual environment empty keeps that ordering
harmless. ``activate_this.py`` already adds entries to the front of
``sys.path``, so this concern does not apply to that path.

Where possible, prefer giving each WSGI application its own daemon
process group (the previous section); that avoids in-script
activation entirely.

Embedded Mode (Single Application)
----------------------------------

Running a single WSGI application in embedded mode is similar to
the daemon-mode-single-application case but without the
``WSGIDaemonProcess`` and ``WSGIProcessGroup`` directives::

    WSGIScriptAlias / /some/path/project/myapp.wsgi

    WSGIApplicationGroup %{GLOBAL}

    <Directory /some/path/project>
        Require all granted
    </Directory>

``WSGIApplicationGroup %{GLOBAL}`` still forces the application
into the main Python interpreter context of each Apache worker
process, for the same reason as before.

To point at a virtual environment in embedded mode, use the
``WSGIPythonHome`` directive::

    WSGIPythonHome /usr/local/venvs/myapp

Note that ``WSGIPythonHome`` applies to the whole Apache instance,
not to a single ``VirtualHost``. If your WSGI application is
configured inside a ``VirtualHost``, the ``WSGIPythonHome``
directive must still go at the server-config level, outside any
``VirtualHost`` block.

Embedded Mode (Multiple Applications)
-------------------------------------

Running multiple WSGI applications in embedded mode mirrors the
multiple-applications-in-one-daemon-process-group case. Each
application runs in its own Python sub-interpreter context to
avoid the framework-multiplicity issue.

Mounting each application explicitly::

    WSGIScriptAlias /myapp3 /some/path/project/myapp3.wsgi
    WSGIScriptAlias /myapp2 /some/path/project/myapp2.wsgi
    WSGIScriptAlias / /some/path/project/myapp1.wsgi

    <Directory /some/path/project>
        Require all granted
    </Directory>

Or mounting a directory of WSGI scripts::

    WSGIScriptAlias / /some/path/project/

    <Directory /some/path/project>
        Require all granted
    </Directory>

If all applications share a single virtual environment, use
``WSGIPythonHome`` to point at it::

    WSGIPythonHome /usr/local/venvs/myapps

As before, ``WSGIPythonHome`` must be at the server-config level,
outside any ``VirtualHost`` block.

If each application needs its own virtual environment, activate it
from the WSGI script using the ``site.addsitedir()`` approach
shown earlier for daemon mode, and set ``WSGIPythonHome`` to an
empty virtual environment so the underlying Python's
``site-packages`` does not interfere.

Adding Additional Module Directories
------------------------------------

The ``python-home`` option to ``WSGIDaemonProcess`` and the
``WSGIPythonHome`` directive are the right way to point at a
virtual environment. They are not for adding other directories to
Python's module search path.

If you do need to add other directories — for example a directory
containing application modules that aren't installed as a package
— use ``python-path`` for daemon mode::

    WSGIDaemonProcess myapp python-path=/some/path/project

This is added in addition to ``python-home``.

For embedded mode, use the ``WSGIPythonPath`` directive::

    WSGIPythonPath /some/path/project

This is added in addition to ``WSGIPythonHome``.

Either form accepts multiple directories, separated by ``:`` on
UNIX-like systems and ``;`` on Windows.

If you are activating a virtual environment from inside a WSGI
script and need additional directories, modify ``sys.path``
directly in the WSGI script.

A note on legacy practice: ``python-path`` and ``WSGIPythonPath``
were sometimes used to bolt the ``site-packages`` directory of a
virtual environment onto Python's search path. Don't do that —
use the ``python-home`` / ``WSGIPythonHome`` mechanism above
instead.
