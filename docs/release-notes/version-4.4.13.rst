==============
Version 4.4.13
==============

Version 4.4.13 of mod_wsgi can be obtained from:

  https://codeload.github.com/GrahamDumpleton/mod_wsgi/tar.gz/4.4.13

For details on the availability of Windows binaries see:

  https://github.com/GrahamDumpleton/mod_wsgi/tree/master/win32

Bugs Fixed
----------

1. The pip installable 'mod_wsgi' package was failing to install on
OpenShift and Heroku as ``mod_wsgi-apxs`` isn't used for tarball based
installs.

New Features
------------

1. Set environment variables from ``apachectl`` for ``mod_wsgi-express``
about the server environment which can be used in additional Apache
configuration included into the generated configuration. The environment
variables are:

* *MOD_WSGI_SERVER_ROOT* - This is the directory where the generated
  configuration files, startup scripts, etc were placed.
* *MOD_WSGI_WORKING_DIRECTORY* - This is the directory which will be used
  as the current working directory of the process. Would default to being
  the same as ``MOD_WSGI_SERVER_ROOT`` if not overridden.
* *MOD_WSGI_LISTENER_HOST* - The host name or IP on which connections are
  being accepted. This should only be used if the Apache configuration
  variable ``MOD_WSGI_WITH_LISTENER_HOST`` is defined.
* *MOD_WSGI_HTTP_PORT* - The port on which HTTP connections are being accepted.
* *MOD_WSGI_HTTPS_PORT* - The port on which HTTPS connections are being
  accepted. This should only be used if the Apache configuration variable
  ``MOD_WSGI_WITH_HTTPS`` is defined.
* *MOD_WSGI_MODULES_DIRECTORY* - The directory where the Apache modules are
  installed.
* *MOD_WSGI_RUN_USER* - The user that the WSGI application will be run as.
* *MOD_WSGI_RUN_GROUP* - The group that the WSGI application will be run as.
