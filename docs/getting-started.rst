===============
Getting Started
===============

.. warning ::

   Documentation linked here is actually located on the old Google Code
   site and has not yet been transitioned to this site. Some documentation
   on the old site may be out of date, especially anything related to
   running mod_wsgi on Windows. For more details as to why and the links to
   all the old documentation see :doc:`project-status`.

If starting out with mod_wsgi it is recommended you start out with a simple
'Hello World!' type application.

Do not attempt to use a Python web application dependent on a web framework
such as Django, Flask or Pyramid until you have got a basic 'Hello World!'
application running first. The simpler WSGI application will validate that
your mod_wsgi installation is working okay and that you at least understand
the basics of configuring Apache.

You can find a simple 'Hello World!' WSGI application, along with setup
instructions for the traditional way of setting up Apache and mod_wsgi,
described in:

* `Quick Configuration Guide <https://code.google.com/p/modwsgi/wiki/QuickConfigurationGuide>`_

Note that unless you are using Windows, where such a choice is not
available, you should always use daemon mode of mod_wsgi. This is not the
default mode, so you will need to ensure you follow the instructions to
enable daemon mode.

For a simpler way of running a Python WSGI application using mod_wsgi, also
checkout ``mod_wsgi-express``, details of which can currently be found at:

   https://pypi.python.org/pypi/mod_wsgi
