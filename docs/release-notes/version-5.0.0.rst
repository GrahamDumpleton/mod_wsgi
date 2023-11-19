=============
Version 5.0.0
=============

Version 5.0.0 of mod_wsgi can be obtained from:

  https://codeload.github.com/GrahamDumpleton/mod_wsgi/tar.gz/5.0.0

*Note that the major version 5.0 was introduced not because of any new major
features but because from version 5.0 onwards compatability with Python 2.7 is
no longer guaranteed. A minimum Python version of 3.8 will be enforced by the
Python package installation configuration.*

Features Changed
----------------

* The `setuptools` package is now required to be installed in order to use the
  `pip install` method to install mod_wsgi. This is because `distutils` has been
  removed in Python 3.12.

Bugs Fixed
----------

* Fix ability to build mod_wsgi against Apache 2.2. Do note that in general only
  recent versions of Apache 2.4 are supported
