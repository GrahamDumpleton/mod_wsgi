========
mod_wsgi
========

.. note::

   After much procrastination, but also a lack of time to do it anyway,
   a last ditch effort is being made to get documentation for mod_wsgi
   off the old Google Code site before it is archived and shutdown.
   Chances are still that this will not happen and documentation will be
   dumped here at the last minute in an unconverted state and so will
   not be formatted properly, or will simply be in more of a mess than
   it is now. Sorry, but if there were 48 hours in a day then maybe
   something could be done about it, but there isn't, so you will just
   have to be patient. For more details and links to the old
   documentation, while it still exists, see :doc:`project-status`.

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
   configuration
   troubleshooting
   user-guides
   finding-help
   reporting-bugs
   contributing
   source-code
   release-notes
