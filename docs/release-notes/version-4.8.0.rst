=============
Version 4.8.0
=============

Version 4.8.0 of mod_wsgi can be obtained from:

  https://codeload.github.com/GrahamDumpleton/mod_wsgi/tar.gz/4.8.0

Bugs Fixed
----------

* Fixed potential for process crash on Apache startup when the WSGI script
  file or other Python script file were being preloaded. This was triggered
  when ``WSGIImportScript`` was used, or if ``WSGIScriptAlias`` or
  ``WSGIScriptAliasMatch`` were used and both the ``process-group`` and
  ``application-group`` options were used with those directives.

  The potential for this problem arising was extremely high on Alpine Linux,
  but seem to be very rare on a full Linux of macOS distribution where glibc
  was being used.
