.. toctree::
   :maxdepth: 1
   :hidden:

   project-status
   security-issues
   getting-help
   reporting-bugs
   release-notes

mod_wsgi
========

.. note::

   Documentation for mod_wsgi is being transitioned here from the old
   Google Code site. For more details and links to the old documentation
   see :doc:`project-status`.

The mod_wsgi package implements a simple to use Apache module which can
host any Python web application which supports the Python WSGI_
specification.

The package can be installed in two forms. The first is as a traditional
Apache module installed into an existing Apache installation. Following
this path you will need to manually configure Apache to load mod_wsgi and
then pass through web requests to your WSGI application.

The second way of installing mod_wsgi is to install it from PyPi_ using the
Python ``pip`` command. This builds and installs mod_wsgi into your Python
installation or virtual environment. The program ``mod_wsgi-express`` will
then be available, allowing you to run up Apache with mod_wsgi from the
command line with an automatically generated configuration. This
approach does not require you to perform any configuration of Apache
yourself.

Both installation types are suitable for production deployments. The latter
approach using ``mod_wsgi-express`` is the best solution if wishing to use
Apache and mod_wsgi within a Docker container to host your WSGI application.
This latter approach is also a better choice when developing your Python
web application due to being able to be run directly within your terminal.

.. _WSGI: http://www.python.org/dev/peps/pep-0333/
.. _PyPi: http://pypi.python.org/pypi/mod_wsgi
