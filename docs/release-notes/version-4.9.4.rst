=============
Version 4.9.4
=============

Version 4.9.4 of mod_wsgi can be obtained from:

  https://codeload.github.com/GrahamDumpleton/mod_wsgi/tar.gz/4.9.4

Bugs Fixed
----------

* Apache 2.4.54 changed the default value for ``LimitRequestBody`` from 0, which
  indicates there is no limit, to 1Gi. If the Apache configuration supplied with
  a distribution wasn't explicitly setting ``LimitRequestBody`` to 0 at global
  server scope for the purposes of documenting the default, and it was actually
  relying on the compiled in default, then when using mod_wsgi daemon mode, if a
  request body size greater than 1Gi was encountered the mod_wsgi daemon mode
  process would crash.

* Fix ability to build mod_wsgi against Apache 2.2. Do note that in general only
  recent versions of Apache 2.4 are supported
