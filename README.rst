========
mod_wsgi
========

mod_wsgi is an Apache HTTP Server module for hosting Python web
applications that implement the WSGI specification (`PEP 3333`_). It
has been used in production deployments for over 15 years and
continues to be actively maintained.

mod_wsgi requires Python 3.10 or later and Apache 2.4. The 6.x
release line is the current focus of development; see the
documentation for the full version support policy.

Documentation
-------------

Full documentation for mod_wsgi is published at:

* https://www.modwsgi.org

That site covers installation on the various supported platforms,
the complete reference for ``WSGI`` configuration directives, the
error code reference for ``WSGI####`` log messages, deployment and
hardening guides, and troubleshooting.

The documentation sources live under ``docs`` in this repository
and are built with Sphinx.

Releases
--------

mod_wsgi is published on the Python Package Index in two forms:

* `mod_wsgi`_ on PyPI builds the mod_wsgi Apache module against an
  existing Apache and Python installation on your host, and
  installs the ``mod_wsgi-express`` command-line wrapper for
  running Apache with a generated configuration tuned for hosting
  a single WSGI application.

* `mod_wsgi-standalone`_ on PyPI additionally installs a private
  build of Apache into your Python environment, for use on
  UNIX-like systems where no system Apache is available.

Reporting bugs
--------------

File bug reports and feature requests on the GitHub issue tracker:

* https://github.com/GrahamDumpleton/mod_wsgi/issues

Before filing a bug report, work through the troubleshooting guide
in the documentation. A substantial share of reports against
mod_wsgi turn out to be configuration, application, or third-party
package issues rather than mod_wsgi bugs.

For suspected security issues, do not open a public issue. Submit a
private security advisory via GitHub:

* https://github.com/GrahamDumpleton/mod_wsgi/security/advisories/new

See the security issues page in the documentation for the full
disclosure process and the list of past CVEs.

Contributing
------------

Pull requests are welcome. Small fixes and self-contained features
can be sent straight through. For larger changes it is worth opening
an issue first to discuss the approach, since mod_wsgi sits across
both the Apache and CPython C APIs and the relevant context is not
always obvious from the code alone.

If you have hit a problem or have an idea but writing the code
yourself would be more friction than help, describing it in an issue
is just as useful. The maintainer is usually quicker at producing a
fix or a small feature in this code base than a first-time
contributor would be.

Sponsorship is set up through GitHub Sponsors:

* https://github.com/sponsors/GrahamDumpleton

Building from source
--------------------

The repository contains:

* ``src/server`` for the Apache module sources (C).
* ``src/express`` and the rest of ``src`` for the Python-side
  package that includes ``mod_wsgi-express`` and the diagnostics
  WSGI applications.
* ``docs`` for the Sphinx documentation published to
  https://www.modwsgi.org.
* ``tests`` for the test suite and sample WSGI applications used by
  it.
* ``scripts`` for helper scripts, including the test runner.

Building from source requires a complete Apache installation
including its development headers (``apache2-dev`` or
``httpd-devel`` depending on distribution), and the Python
development headers. See the documentation's installation page for
the full prerequisites.

For an editable development build into a virtual environment::

    uv pip install -e . --no-cache

To run the test suite::

    ./scripts/run-tests.sh

License
-------

mod_wsgi is distributed under the Apache License, Version 2.0. See
the ``LICENSE`` file in this repository for the full text.

.. _PEP 3333: https://peps.python.org/pep-3333/
.. _mod_wsgi: https://pypi.org/project/mod_wsgi/
.. _mod_wsgi-standalone: https://pypi.org/project/mod_wsgi-standalone/
