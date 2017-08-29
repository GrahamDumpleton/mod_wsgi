==============
Version 4.5.18
==============

Version 4.5.18 of mod_wsgi can be obtained from:

  https://codeload.github.com/GrahamDumpleton/mod_wsgi/tar.gz/4.5.18

Features Changed
----------------

* When using ``--url-alias`` with ``mod_wsgi-express`` and the target of
  the URL doesn't exist, it will now be assumed that it will be a directory
  rather than a file, when finally created. This is to accomodate where
  may have used ``--setup-only`` option or ``setup-server`` command to 
  pre-generate config files before the directory is created.
