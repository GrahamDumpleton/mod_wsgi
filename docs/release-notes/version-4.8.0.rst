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

* Include a potential workaround so that virtual environment work on Windows.

  Use of virtual environments in embedded systems on Windows has been broken
  ever since ``python -m venv`` was introduced.

  Initially ``virtualenv`` was not affected, although when it changed to
  use the new style Python virtual environment layout the same as
  ``python -m venv`` it also broke. This was with the introduction of about
  ``virtualenv`` version 20.0.0.

  The underlying cause is lack of support for using virtual environments in
  CPython for the new style virtual environments. The bug has existed in
  CPython since back in 2014 and has not been fixed. For details of the
  issue see https://bugs.python.org/issue22213.

  For non Window systems a workaround had been used to resolve the problem,
  but the same workaround has never worked on Windows. The change in this
  version tries a different workaround for Windows environments.
