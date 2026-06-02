==================
WSGICallableObject
==================

:Description: Sets the name of the WSGI application callable.
:Syntax: ``WSGICallableObject`` *name*
:Default: ``WSGICallableObject application``
:Context: server config, virtual host, directory, .htaccess
:Override: ``FileInfo``

The WSGICallableObject directive can be used to override the name of the
Python callable object in the script file which is used as the entry point
into the WSGI application.

By default the entry point is the object named ``application``. Setting
this directive lets you point at a different name, which is useful when
the script file follows a framework convention that uses a different
name. For example, Flask applications conventionally name the WSGI
callable ``app``::

  WSGICallableObject app

Note that the name of the callable object must be an object present at
global scope within the WSGI script file. It is not possible to use a dotted
path to refer to a sub object of a module imported by the WSGI script file.
