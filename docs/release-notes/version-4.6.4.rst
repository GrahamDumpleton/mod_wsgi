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

* Installing mod_wsgi on Windows would fail as hadn't exclude mod_wsgi
  daemon mode specific code from Windows build. This would result in compile
  time error about ``wsgi_daemon_process`` being undefined. This problem
  was introduced to Windows in version 4.6.0. A prior attempt to fix this
  in 4.6.3 missed one place in the code which needed to be changed.
