========
mod_wsgi
========

The mod_wsgi package implements a simple to use Apache module which can
host any Python web application which supports the Python WSGI_
specification. The package can be installed in two different ways
depending on your requirements.

The first is as a traditional Apache module installed into an existing
Apache installation. Following this path you will need to manually
configure Apache to load mod_wsgi and pass through web requests to your
WSGI application.

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
It is also a better choice when using mod_wsgi during the development of
your Python web application as you will be able to run it directly from
your terminal.

.. _WSGI: http://www.python.org/dev/peps/pep-3333/
.. _PyPi: http://pypi.python.org/pypi/mod_wsgi

.. toctree::
   :maxdepth: 1
   :hidden:

   project-status
   security-issues
   getting-started
   requirements
   installation
   troubleshooting
   user-guides
   configuration
   finding-help
   reporting-bugs
   contributing
   source-code
   release-notes
