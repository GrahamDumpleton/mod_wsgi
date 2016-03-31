=============
Version 4.5.0
=============

Version 4.5.0 of mod_wsgi can be obtained from:

  https://codeload.github.com/GrahamDumpleton/mod_wsgi/tar.gz/4.5.0

New Features
------------

1. Added additional internal performance monitoring features, included per
   request event mechanism for getting extended metrics on a per request
   basis. This includes details like per request CPU burn, which along with
   process level CPU burn and thread utilisation can be used to better tune
   processes/threads settings.
