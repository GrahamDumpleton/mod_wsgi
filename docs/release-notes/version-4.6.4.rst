=============
Version 4.6.4
=============

Version 4.6.4 of mod_wsgi can be obtained from:

  https://codeload.github.com/GrahamDumpleton/mod_wsgi/tar.gz/4.6.4

Bugs Fixed
----------

* In more recent Python versions, the config directory in the Python
  installation incorporates the platform name. This directory was added as
  an additional directory to search for Python shared libraries when
  installing using the ``setup.py`` file or ``pip``. It should not even be
  needed for newer Python versions but still check for older Python
  versions. The only issue arising from the wrong directory, not incorporating
  the platform name, being used, was a linker warning about the directory
  not being present.
