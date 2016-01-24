====================
WSGIRestrictEmbedded
====================

:Description: Enable restrictions on use of embedded mode.
:Syntax: ``WSGIRestrictEmbedded On|Off``
:Default: ``WSGIRestrictEmbedded Off``
:Context: server config

The WSGIRestrictEmbedded directive determines whether mod_wsgi embedded
mode is enabled or not. If set to 'On' and the restriction on embedded mode
is therefore enabled, any attempt to make a request against a WSGI
application which hasn't been properly configured so as to be delegated to
a daemon mode process will fail with a HTTP internal server error response.

This option does not exist on Windows, or Apache 1.3 or any other
configuration where daemon mode is not available.
