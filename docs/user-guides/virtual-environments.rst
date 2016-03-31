====================
Virtual Environments
====================

This document contains information about how to make use of Python virtual
environments such as created by Ian Bicking's virtualenv with mod_wsgi.

  * http://pypi.python.org/pypi/virtualenv

The purpose of such Python virtual environments is to allow one to create
multiple distinct Python environments for the same version of Python, but
with different sets of Python modules and packages installed into the
Python 'site-packages' directory.

A virtual Python environment is useful where it is necessary to run
multiple WSGI applications which have conflicting requirements as to what
version of a Python module or package needs to be installed. They can also
be used where Apache and daemon mode of mod_wsgi is used to host WSGI
applications for different users and each user wants to be able to
separately install their own Python modules and packages.

Note that aspects of the configuration described here will not work if
mod_python is being loaded into Apache at the same time as mod_wsgi. This
is because mod_python will in that case be responsible for initialising the
Python interpreter, thereby overriding what mod_wsgi is trying to do. For
best results, you should therefore use only mod_wsgi and not try and use
mod_python on the same server at the same time.

Baseline Environment
--------------------

The first step in using virtual environments with mod_wsgi is to point
mod_wsgi at a baseline Python environment. This step is actually optional
and if not done the main Python installation for the system, usually that
which mod_wsgi was compiled for, would be used as the baseline environment.

Although the main Python installation can be used, especially in a shared
environment where daemon mode of mod_wsgi is used to host WSGI applications
for different users, it is better to make the baseline environment a virgin
environment with an effectively empty 'site-packages' directory. This way
there is no possibility of conflicts between modules and packages in a users
individual Python virtual environment and the baseline environment.

To create a virgin environment using the 'virtualenv' program, the
'--no-site-packages' option should be supplied when creating the environment::

    $ cd /usr/local/pythonenv

    $ virtualenv --no-site-packages BASELINE
    New python executable in BASELINE/bin/python
    Installing setuptools............done.

Note that the version of Python from which this baseline environment is
created must be the same version of Python that mod_wsgi was compiled for.
It is not possible to mix environments based on different major/minor
versions of Python.

Once the baseline Python environment has been created, the WSGIPythonHome
directive should be defined within the global part of the main Apache
configuration files. The directive should refer to the top level directory
for the baseline environment created by the 'virtualenv' script::

    WSGIPythonHome /usr/local/pythonenv/BASELINE

This Python environment will now be used as the baseline environment for
all WSGI applications running under mod_wsgi, whether they be run in
embedded mode or daemon mode.

There is no need to set the WSGIPythonHome directive if you want to use
the main Python installation as the baseline environment.

Application Environments
------------------------

If for a specific WSGI application you have created a dedicated virtual
environment, then this environment can now be overlayed on top of the
baseline environment. If the baseline environment was a virgin environment,
this virtual environment should also be initially created as a virgin
environment.

For example, to create a virtual environment dedicated to developing Pylons
applications the following would be used::

    $ virtualenv --no-site-packages PYLONS-1
    New python executable in
    PYLONS-1/bin/python
    Installing setuptools............done.

    $ source PYLONS-1/bin/activate 

    (PYLONS-1)$ easy_install Pylons
    Searching for Pylons
    .......

The Pylons instructions for creating a Pylons application would then be
followed and the application tested using the Pylons inbuilt web server.

As an additional step however, the WSGI script file described in the
instructions would be modified to overlay the virtual environment for the
application on top of the baseline environment. This would be done by
adding at the very start of the WSGI script file the following::

    import site
    site.addsitedir('/usr/local/pythonenv/PYLONS-1/lib/python2.5/site-packages')

Note that in this case the full path to the 'site-packages' directory for
the virtual environment needs to be specified and not just the root of
the virtual environment.

Using 'site.addsitedir()' is a bit different to simply adding the directory
to 'sys.path' as the function will open up any '.pth' files located in the
directory and process them. This is necessary to ensure that any special
directories related to Python eggs are automatically added to 'sys.path'.

Note that although virtualenv includes the script 'activate_this.py', which
the virtualenv documentation claims should be invoked using 'execfile()' in
the context of mod_wsgi, you may want to be cautious using it. This is
because the script modifies 'sys.prefix' which may actually cause problems
with the operation of mod_wsgi or Python modules already loaded into the
Python interpreter, if the code is dependent on the value of 'sys.prefix'
not changing. The WSGIPythonHome directive already described should instead
be used if wanting to associate Python as a whole with the virtual
environment.

Despite that, the 'activate_this.py' script is an attempt to resolve an
issue with how 'site.addsitedir()' works. That is that any new directories
which are added to 'sys.path' by 'site.addsitedir()' are actually appended
to the end. The problem with this in the context of mod_wsgi is that if
WSGIPythonHome was not used to associate mod_wsgi with a virgin baseline
environment, then any packages/modules in the main Python installation will
still take precedence over those in the virtual environment.

To work around this problem, what 'activate_this.py' does is invoke
'site.addsitedir()' but then also reorders 'sys.path' so any newly added
directories are shifted to the front of 'sys.path'. This will then ensure
that where there are different versions of packages in the virtual environment
that they take precedence over those in the main Python installation.

As explained, because 'activate_this.py' is doing other things which may
not be appropriate in the context of mod_wsgi, if unable to set WSGIPythonHome
to point mod_wsgi at a virgin baseline environment, instead of just calling
'site.addsitedir()' you should use the code::

    ALLDIRS = ['usr/local/pythonenv/PYLONS-1/lib/python2.5/site-packages']

    import sys 
    import site 

    # Remember original sys.path.
    prev_sys_path = list(sys.path) 

    # Add each new site-packages directory.
    for directory in ALLDIRS:
      site.addsitedir(directory)

    # Reorder sys.path so new directories at the front.
    new_sys_path = [] 
    for item in list(sys.path): 
        if item not in prev_sys_path: 
            new_sys_path.append(item) 
            sys.path.remove(item) 
    sys.path[:0] = new_sys_path 

If you still want to use the activation script from virtualenv, then use::

    activate_this = '/usr/local/pythonenv/PYLONS-1/bin/activate_this.py'
    execfile(activate_this, dict(__file__=activate_this))

If the fact that 'sys.prefix' has been modified doesn't give an issue, then
great. If you see subtle unexplained problems that may be linked to the
change to 'sys.prefix', then use the more long handed approach above whereby
'site.addsitedir()' is used directly and 'sys.path' reorderd subsequently.

Process Environments
--------------------

When 'site.addsitedir()' is used from a WSGI script file to overlay a
virtual environment on top of the baseline environment, it is only applied
to the specific Python interpreter instance that the application has been
delegated to run in. This means that WSGI applications running in the same
process but within different Python interpreter instances can use different
virtual environments.

At the same time though, if needing all WSGI applications running in the
same process but within different Python interpreters, to use the same
virtual environment, you would need to setup 'sys.path' in the WSGI script
file for all applications.

Alternatively, if using mod_wsgi 2.0 and embedded mode, the WSGIPythonPath
directive can be used to setup the virtual environment for all Python
interpreters created within the process in one step::

    WSGIPythonPath /usr/local/pythonenv/PYLONS-1/lib/python2.5/site-packages

Similarly, if using mod_wsgi 2.0 or later and daemon mode, the
'python-path' option to the WSGIDaemonProcess directive can be used to
setup the virtual environment::

    WSGIDaemonProcess pylons \
     python-path=/usr/local/pythonenv/PYLONS-1/lib/python2.5/site-packages

Note that WSGIPythonPath does not have this effect for mod_wsgi prior to
version 2.0. This is because in older versions WSGIPythonPath merely added
any listed directories to 'sys.path', whereas in mod_wsgi 2.0 and later it
calls 'site.addsitedir()' for each listed directory.

Do note though that all mod_wsgi 2.X versions prior to mod_wsgi 2.4 do not
perform the reordering of 'sys.path' as explained previously, when using
WSGIPythonPath directive or 'python-path' option for WSGIDaemonProcess.
Thus, you would need to be using WSGIPythonHome to reference a virgin
baseline environment when using mod_wsgi 2.3 or earlier if the standard
Python site-packages directory has conflicting packages. For mod_wsgi 2.4
onwards this is not an issue and a virtual environments site-packages will
always override that in standard Python installation.
