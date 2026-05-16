========
mod_wsgi
========

mod_wsgi is an Apache module that hosts Python web applications which
implement the WSGI_ specification (PEP 3333). It has been used in
production deployments for over 15 years and continues to be actively
maintained.

mod_wsgi requires Python 3.10 or later and Apache 2.4. It is regularly
used on Linux and macOS; Windows support under the 6.x line is
provisional — see :doc:`project-status` for details.

Two ways to use mod_wsgi
------------------------

* As a **traditional Apache module** loaded into an existing Apache
  installation. You configure Apache by hand to load the module and
  route requests to your WSGI application. The module itself can be
  built from source or, on Linux, installed from a distribution
  package (deb/rpm) where one is available. See :doc:`installation`.

* As **mod_wsgi-express**, a pip-installable Python package that wraps
  Apache and mod_wsgi behind a single command and generates the Apache
  configuration for you. This is the recommended path for Docker
  containers and for running mod_wsgi during development. See
  :doc:`user-guides/mod-wsgi-express-quickstart`.

Both approaches are suitable for production use.

Where to start
--------------

* Want background on how mod_wsgi works with Apache and the common
  deployment shapes? See :doc:`how-mod-wsgi-works`.
* New to mod_wsgi? Start with :doc:`getting-started`.
* Already running Apache and want to add WSGI support? See
  :doc:`installation` and the
  :doc:`user-guides/quick-configuration-guide`.
* Want a live monitoring UI alongside your mod_wsgi install? See
  :doc:`user-guides/external-telemetry-service`, which uses the
  separately distributed ``mod_wsgi-telemetry`` ingester on PyPI.
* Looking up a specific ``WSGIxxx`` directive? See :doc:`configuration`.
* Saw a ``WSGI####`` error code in your logs? See
  :doc:`error-reference`.
* Stuck or have a question? See :doc:`troubleshooting` and
  :doc:`finding-help`.

.. _WSGI: https://peps.python.org/pep-3333/

.. toctree::
   :caption: About
   :maxdepth: 1

   how-mod-wsgi-works
   project-status
   security-issues

.. toctree::
   :caption: Getting started
   :maxdepth: 1

   getting-started
   requirements
   installation

.. toctree::
   :caption: User guides
   :maxdepth: 2

   user-guides

.. toctree::
   :caption: Reference
   :maxdepth: 1

   configuration
   error-reference

.. toctree::
   :caption: Help and community
   :maxdepth: 1

   troubleshooting
   finding-help
   reporting-bugs
   contributing
   source-code

.. toctree::
   :caption: Releases
   :maxdepth: 1

   release-notes
