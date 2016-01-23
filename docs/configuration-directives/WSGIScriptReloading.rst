===================
WSGIScriptReloading
===================

:Description: Enable/Disable detection of WSGI script file changes.
:Syntax: ``WSGIScriptReloading On|Off``
:Default: ``WSGIScriptReloading On``
:Context: server config, virtual host, directory, .htaccess
:Override: ``FileInfo``

The WSGIScriptReloading directive can be used to control whether changes to
WSGI script files trigger the reloading mechanism. By default script
reloading is enabled and a change to the WSGI script file will trigger
whichever reloading mechanism is appropriate to the mode being used.
