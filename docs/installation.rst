============
Installation
============

mod_wsgi can be installed in several ways. The right choice depends
on what you want to run, who manages the host, and which platform
you are on.

For the full requirements list (Python and Apache versions, build
toolchain, distribution package names) see :doc:`requirements`.

Choosing an install method
--------------------------

* **Want to try mod_wsgi quickly, or run it inside a Python virtual
  environment alongside your application's other dependencies?**
  Install from PyPI with ``pip install mod_wsgi``. This also gives
  you the ``mod_wsgi-express`` admin command for running a private
  Apache plus mod_wsgi instance from the command line. See
  :doc:`user-guides/installation-from-pypi`.

* **Running on Linux and want a system-wide install managed by your
  distribution's package manager?** Install the distribution
  package. See :doc:`user-guides/installation-on-linux`.

* **Want a from-source build that installs into Apache the
  traditional way (``configure`` / ``make`` / ``make install``)?**
  See :doc:`user-guides/quick-installation-guide`.

Platform-specific notes
-----------------------

* :doc:`user-guides/installation-on-macosx` — Apple removed the
  build tooling needed to use the system Apache, so macOS uses an
  Apache installed via Homebrew.
* :doc:`user-guides/installation-on-windows` — Windows install is
  via pip only; daemon mode and ``mod_wsgi-express start-server``
  are not available on Windows.

Notes on currency
-----------------

The version of mod_wsgi shipped by your Linux distribution may lag
the current upstream release; long-term-support distributions in
particular can lag upstream by some time. The age and currency of
the packaged version varies by distribution and release. Check the
version your distribution provides; if security currency or access
to recent fixes matters for your deployment, weigh that against
installing from PyPI or from source. See :doc:`project-status` for
the project's overall version support policy.

After installing
----------------

* :doc:`getting-started` — first-run walkthrough using
  ``mod_wsgi-express``.
* :doc:`user-guides/quick-configuration-guide` — manual Apache
  configuration for your WSGI application.
* :doc:`user-guides/configuration-guidelines` — richer
  configuration examples.
* :doc:`configuration` — Apache directive reference.
* :doc:`troubleshooting` — what to do if something doesn't work.
