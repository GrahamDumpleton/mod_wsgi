=============
Version 5.0.3
=============

Version 5.0.3 of mod_wsgi can be obtained from:

  https://codeload.github.com/GrahamDumpleton/mod_wsgi/tar.gz/5.0.3

Features Changed
----------------

* Django community has started adopting use of `pathlib` module when defining
  paths in the Django settings file. This would cause issues for the
  `runmodwsgi` management command for Django as it expected strings for
  `STATIC_ROOT` setting. The code has been updated to always convert
  `STATIC_ROOT` to a string in `runmodwsgi` to cope with people using `pathlib`
  module in their Django settings file.
