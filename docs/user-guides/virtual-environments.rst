====================
Virtual Environments
====================

This document contains information about how to use Python virtual
environments with mod_wsgi. You can use a Python virtual environment
created using `virtualenv`_ and `virtualenvwrapper`_, or if using Python 3,
the ``pyvenv`` or ``python -m venv`` commands.

The purpose of a Python virtual environments is to allow one to create
multiple distinct Python environments for the same version of Python, but
with different sets of Python modules and packages installed. It is
recommended that you always use Python virtual environments and not install
additional Python packages direct into your Python installation.

A Python virtual environment is also required where it is necessary to run
multiple WSGI applications which have conflicting requirements as to what
version of a Python module or package needs to be installed. They can also
be used when distinct mod_wsgi daemon process groups are used to host WSGI
applications for different users and each user needs to be able to
separately install their own Python modules and packages.

How you configure mod_wsgi or setup your WSGI application script file for a
Python virtual environment will depend on your specific requirements. The
more common scenarios are explained below.

Location of the Virtual Environment
-----------------------------------

Whichever method you use to create a Python virtual environment, before you
use it with mod_wsgi, you should validate what the location of the Python
virtual environment is. If using `virtualenvwrapper`_ this may be a non
obvious directory hidden away under your home directory.

The way to determine the location of the Python virtual environment is to
activate the Python virtual environment from an interactive shell so it is
being used, and then run the command::

    python -c 'import sys; print(sys.prefix)'

This will output the directory path you will use when setting up mod_wsgi
to use the Python virtual environment. For the purposes of the examples
below, it is assumed the location of any Python virtual environments are
under the ``/usr/local/venvs`` directory. A specific Python virtual
environment may thus return for ``sys.prefix``::

    /usr/local/venvs/example

Note that this should be the root directory of the Python virtual
environment, which in turn contains the ``bin`` and ``lib`` directories for
the Python virtual environment. It is a common mistake when setting up a
Python virtual environment with mod_wsgi to use the full path to the
``python`` executable instead of the root directory. That will not work, so
do not use the path for the ``python`` executable as the location of the
Python virtual environment, it has to be the root directory.

Do be aware that the user that Apache runs your code as will need to be
able to access the Python virtual environment. On some Linux distributions,
the home directory of a user account is not accessible to other users.
Rather than change the permissions on your home directory, it might be
better to consider locating your WSGI application code and any Python
virtual environment outside of your home directory.

Virtual Environment and Python Version
--------------------------------------

When using a Python virtual environment with mod_wsgi, it is very important
that it has been created using the same Python installation that mod_wsgi
was originally compiled for. It is not possible to use a Python virtual
environment to force mod_wsgi to use a different Python version, or even a
different Python installation.

You cannot for example force mod_wsgi to use a Python virtual environment
created using Python 3.5 when mod_wsgi was originally compiled for Python
2.7. This is because the Python library for the Python installation it was
originally compiled against is linked directly into the mod_wsgi module.
In other words, Python is embedded within mod_wsgi. When mod_wsgi is used
it does not run the command line ``python`` program to run the interpreter
and thus why you can't force it to use a different Python installation.

The problem in trying to force mod_wsgi to use a different Python
installation than what it was compiled for, even where it is the same
Python version, is that the Python installation may itself not have been
compiled with the same options. This is especially a problem when it comes
to issues around how Python stores Unicode characters in memory.

The end result is that if you want to use a different Python installation
or version than what mod_wsgi was originally compiled for, you would need
to re-install mod_wsgi such that it is compiled for the Python installation
or version you do want to use. Do not try and use a Python virtual
environment from one Python installation or version with mod_wsgi, when
mod_wsgi was compiled for a different one.

Daemon Mode (Single Application)
--------------------------------

The preferred way of setting up mod_wsgi is to run each WSGI application
in its own daemon process group. This is called daemon mode. A typical
configuration for running a WSGI application in daemon mode would be::

    WSGIDaemonProcess myapp

    WSGIProcessGroup myapp
    WSGIApplicationGroup %{GLOBAL}

    WSGIScriptAlias / /some/path/project/myapp.wsgi

    <Directory /some/path/project>
        Require all granted
    </Directory>

The ``WSGIDaemonProcess`` directive defines the daemon process group. The
``WSGIProcessGroup`` directive indicates that the WSGI application should be
run within the defined daemon process group.

As only the single application is being run within the daemon process
group, the ``WSGIApplicationGroup`` directive is also being used. When this
is used with the ``%{GLOBAL}`` value, it forces the WSGI application to run
in the main Python interpreter context of each process. This is preferred
in this scenario as some third party packages for Python which include C
extensions will not run in the Python sub interpreter contexts which
mod_wsgi would use by default. By using the main Python interpreter context
you eliminate the possibility of such third party packages for Python
causing problems.

To modify the configuration for this scenario to use a Python virtual
environment, all you need to do is add the ``python-home`` option to the
``WSGIDaemonProcess`` directive resulting in::

    WSGIDaemonProcess myapp python-home=/usr/local/venvs/myapp

All the additonal Python packages and modules would then be installed into
that Python virtual environment.

Daemon Mode (Multiple Applications)
-----------------------------------

If instead of running each WSGI application in a separate daemon process
group as is the recommended practice, you are running multiple WSGI
applications in one daemon process group, a different approach to using
Python virtual environments is required.

For this scenario there are various ways the configuration could be set
up. If mounting each WSGI application explicitly you might be using::

    WSGIDaemonProcess myapps

    WSGIProcessGroup myapps

    WSGIScriptAlias /myapp3 /some/path/project/myapp3.wsgi
    WSGIScriptAlias /myapp2 /some/path/project/myapp2.wsgi

    WSGIScriptAlias / /some/path/project/myapp1.wsgi

    <Directory /some/path/project>
        Require all granted
    </Directory>

If instead the directory containing the WSGI application script files is
being mounted, you might be using::

    WSGIDaemonProcess myapps

    WSGIProcessGroup myapps

    WSGIScriptAlias / /some/path/project/

    <Directory /some/path/project>
        Require all granted
    </Directory>

The use of the ``WSGIDaemonProcess`` and ``WSGIProcessGroup`` is the same as
before, however the ``WSGIApplicationGroup`` directive is not being used.

When the ``WSGIApplicationGroup`` directive isn't being used to override
which Python interpreter context is being used, each WSGI application will
be run in its own Python sub interpreter context of the processes. This is
necessary as often WSGI application frameworks (Django being a prime
example), do not support running more than one instance of a WSGI
application using the framework, in the same Python interpreter context at
the same time.

In this scenario of running multiple WSGI applications in the same daemon
process group, more than one change is possibly required. The changes
required depend on whether or not all WSGI applications should share the
same Python virtual environment.

If all of the WSGI applications should share the same Python virtual
environment, then the same change as was performed above for the single
application case would be made. That is, add the ``python-home`` option
to the ``WSGIDaemonProcess`` directive::

    WSGIDaemonProcess myapp python-home=/usr/local/venvs/myapps

All the additonal Python packages and modules that any of the WSGI
applications required would then be installed into that Python virtual
environment. Because it is a shared environment, they must all use the same
version of any specific Python package or module.

If instead of all WSGI applications using the same Python virtual
environment each needed their own, then a change will instead need to be
made in each of the WSGI script files for the applications.

How this is done will depend on how the Python virtual environment is
created.

If the Python virtual environment is created using `virtualenv`_ or
`virtualenvwrapper`_, the WSGI script for each application should be
modified to include code of the following form::

    python_home = '/usr/local/envs/myapp1'

    activate_this = python_home + '/bin/activate_this.py'
    execfile(activate_this, dict(__file__=activate_this))

Because each WSGI application is to use a separate Python virtual
environment, the value of the ``python_home`` variable would be set
differently for each WSGI script file, with it referring to the root
directory of the respective Python virtual environments.

This code should be placed in the WSGI script file before any other module
imports in the WSGI script file, with the exception of ``from __future__``
imports used to enable Python feature flags.

Important to note is that when the Python virtual environment is activated
from within the WSGI script, what happens is a bit different to when the
``python-home`` option to ``WSGIDaemonProcess`` is used.

When activating the Python virtual environment from within the WSGI script
file, only the ``site-packages`` directory from the Python virtual
environment is being used. This directory will be added to the Python
module search path, along with any additional directories related to the
``site-packages`` directory registered using ``.pth`` files present in the
``site-packages`` directory. This will be placed at the start of the
existing ``sys.path``.

The consequence of this is that the Python virtual environment isn't
completely overriding the original Python installation the Python virtual
environment was created from. This means that if the main Python
installation had additional Python packages installed they will also
potentially be visible to the WSGI application.

That this occurs could cause confusion as you might for example think you
had all the packages you require listed in your ``requirements.txt`` file
for ``pip``, but didn't and so a package may not have been installed. If
that package was installed in the main Python installation, it would be
picked up from there, but it might be the wrong version and have
dependencies on versions of other packages for which you have different
versions installed in your Python virtual environment and which are found
instead of those in the main Python installation.

To avoid such problems, when activating the Python virtual environment
from within the WSGI script file, it is necessary to still set the
``python-home`` option of the ``WSGIDaemonProcess`` directive, but set it to
an empty Python virtual environment which has had no additional packages
installed::

    WSGIDaemonProcess myapp python-home=/usr/local/venvs/empty

By doing this, the main Python installation will not be consulted and
instead it will fallback to the empty Python virtual environment. This
Python virtual environment should remain empty and you should not install
additional Python packages or modules into it, or you will cause the same
sort of conflicts that can arise with the main Python installation when it
was being used.

When needing to activate the Python virtual environment from within the
WSGI script file as described, it is preferred that you be using the either
`virtualenv`_ or `virtualenvwrapper`_ to create the Python virtual
environment. This is because they both provide the ``activate_this.py``
script file which does all the work of setting up ``sys.path``. When you
use either ``pyvenv`` or ``python -m venv`` with Python 3, no such
activation script is provided.

So use `virtualenv`_ or `virtualenvwrapper`_ if you can. If you cannot for
some reason and are stuck with ``pyvenv`` or ``python -m venv``, you can
instead use the following code in the WSGI script file::

    python_home = '/usr/local/envs/myapp1'

    import sys
    import site

    # Calculate path to site-packages directory.

    python_version = '.'.join(map(str, sys.version_info[:2]))
    site_packages = python_home + '/lib/python%s/site-packages' % python_version

    # Add the site-packages directory.

    site.addsitedir(site_packages)

As before this code should be placed in the WSGI script file before any
other module imports in the WSGI script file, with the exception of ``from
__future__`` imports used to enable Python feature flags.

When using this method, do be aware that the additions to the Python module
search path are made at the end of ``sys.path``. For that reason, you must
set the ``python-home`` option to ``WSGIDaemonProcess`` to the location of
an empty Python virtual environment. If you do not do this, any additional
Python package installed in the main Python installation will hide those in
the Python virtual environment for the application.

There is extra code you could add which would reorder ``sys.path`` to make
it work in an equivalent way to the ``activate_this.py`` script provided
when you use `virtualenv`_ or `virtualenvwrapper`_ but it is messy and more
trouble than it is worth::

    python_home = '/usr/local/envs/myapp1'

    import sys 
    import site 

    # Calculate path to site-packages directory.

    python_version = '.'.join(map(str, sys.version_info[:2]))
    site_packages = python_home + '/lib/python%s/site-packages' % python_version
    site.addsitedir(site_packages)

    # Remember original sys.path.

    prev_sys_path = list(sys.path) 

    # Add the site-packages directory.

    site.addsitedir(site_packages)

    # Reorder sys.path so new directories at the front.

    new_sys_path = [] 

    for item in list(sys.path): 
        if item not in prev_sys_path: 
            new_sys_path.append(item) 
            sys.path.remove(item) 

    sys.path[:0] = new_sys_path 

It is better to avoid needing to manually activate the Python virtual
environment from inside of a WSGI script by using a separate daemon process
group per WSGI application. At the minimum, at least avoid ``pyvenv`` and
``python -m venv``.

Embedded Mode (Single Application)
----------------------------------

The situation for running a single WSGI application in embedded mode is not
much different to running a single WSGI application in daemon mode. In the
case of embedded mode, there is though no ``WSGIDaemonProcess`` directive.

The typical configuration when running a single WSGI application in
embedded module might be::

    WSGIScriptAlias / /some/path/project/myapp.wsgi

    WSGIApplicationGroup %{GLOBAL}

    <Directory /some/path/project>
        Require all granted
    </Directory>

The ``WSGIDaemonProcess`` and ``WSGIProcessGroup`` directives are gone, but
the ``WSGIApplicationGroup`` directive is still used to force the WSGI
application to run in the main Python interpreter context of each of the
Apache worker processes. This is to avoid those issues with some third
party packages for Python with C extensions as mentioned before.

In this scenario, to set the location of the Python virtual environment
to be used, the ``WSGIPythonHome`` directive is used::

    WSGIPythonHome /usr/local/envs/myapp

Note that if the WSGI application is being setup within the context of an
Apache ``VirtualHost``, the ``WSGIPythonHome`` cannot be placed inside of
the ``VirtualHost``. Instead it must be placed outside of all
``VirtualHost`` definitions. This is because it applies to the whole Apache
instance and not just the single ``VirtualHost``.

Embedded Mode (Multiple Applications)
-------------------------------------

Running multiple applications in embedded mode is also similar to when
running multiple WSGI applications in one daemon process group. You still
need to ensure each WSGI application runs in its own Python sub interpreter
context to avoid potential issues with Python web frameworks that don't
allow more than one WSGI application to be using it at the same time in a
Python interpreter context.

If mounting each WSGI application explicitly you might be using::

    WSGIScriptAlias /myapp3 /some/path/project/myapp3.wsgi
    WSGIScriptAlias /myapp2 /some/path/project/myapp2.wsgi

    WSGIScriptAlias / /some/path/project/myapp1.wsgi

    <Directory /some/path/project>
        Require all granted
    </Directory>

If instead the directory containing the WSGI application script files is
being mounted, you might be using::

    WSGIScriptAlias / /some/path/project/

    <Directory /some/path/project>
        Require all granted
    </Directory>

In this scenario, to set the location of the Python virtual environment
to be used by all WSGI application, the ``WSGIPythonHome`` directive is used::

    WSGIPythonHome /usr/local/envs/myapps

If the WSGI application is being setup within the context of an Apache
``VirtualHost``, the ``WSGIPythonHome`` cannot be placed inside of the
``VirtualHost``. Instead it must be placed outside of all ``VirtualHost``
definitions. This is because it applies to the whole Apache instance and
not just the single ``VirtualHost``.

If each WSGI application needs its own Python virtual environment, then
activation of the Python virtual environment needs to be performed in the
WSGI script itself as explained previously for the case of daemon mode
being used. The ``WSGIPythonHome`` directive should be used to refer to an
empty Python virtual environment if needed to ensure that any additional
Python packages in the main Python installation don't interfere with what
packages are installed in the Python virtual environment for each WSGI
application.

Adding Additional Module Directories
------------------------------------

The ``python-home`` option to ``WSGIDaemonProcess`` and the
``WSGIPythonHome`` directive are the preferred way of specifying the
location of the Python virtual environment to be used. If necessary,
activation of the Python virtual environment can also be performed from the
WSGI script file itself.

If you need to add additional directories to search for Python packages or
modules this can also be done. You may want to do this where you need to
specify where the actual WSGI application is located, where a WSGI script
file needs to import application specific modules.

If you are using daemon mode and want to add additional directories to the
Python module search path, you can use the ``python-path`` option to
``WSGIDaemonProcess``::

    WSGIDaemonProcess myapp python-path=/some/path/project

This option would be in addition to the ``python-home`` option used to
specify where the Python virtual environment is located.

If you are using embedded mode, you can use the ``WSGIPythonPath``
directive::

    WSGIPythonPath /some/path/project

This directive is in addition to the ``WSGIPythonHome`` directive used to
specify where the Python virtual environment is located.

In either case, if you need to specify more than one directory, they can be
separated using a ':' character.

If you are having to activate the Python virtual enviromment from within a
WSGI script and need to add additional directories to the Python module
search path, you should modify ``sys.path`` directly from the WSGI script
file.

Note that prior practice was that these ways of setting the Python module
search path were used to specify the location of the Python virtual
environment. Specifically, they were used to add the ``site-packages``
directory of the Python virtual environment. You should not do that.

The better way to specify the location of the Python virtual environment is
using the ``python-home`` option of the ``WSGIDaemonProcess`` directive for
daemon mode, or the ``WSGIPythonHome`` directive for embedded mode. These
ways of specifying the Python virtual environment have been available since
mod_wsgi 3.0 and Linux distributions have not shipped such an old version
of mod_wsgi for quite some time. If you are using the older way, please
update your configurations.

.. _virtualenv: http://pypi.python.org/pypi/virtualenv
.. _virtualenvwrapper: https://pypi.python.org/pypi/virtualenvwrapper
