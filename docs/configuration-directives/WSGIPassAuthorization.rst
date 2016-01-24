=====================
WSGIPassAuthorization
=====================

:Description: Enable/Disable passing of authorisation headers.
:Syntax: ``WSGIPassAuthorization On|Off``
:Default: ``WSGIPassAuthorization Off``
:Context: server config, virtual host, directory, .htaccess

The WSGIPassAuthorization directive can be used to control whether HTTP
authorisation headers are passed through to a WSGI application in the
``HTTP_AUTHORIZATION`` variable of the WSGI application environment when
the equivalent HTTP request headers are present. This option would need to
be set to ``On`` if the WSGI application was to handle authorisation
rather than Apache doing it.

Authorisation headers are not passed through by default as doing so could
leak information about passwords through to a WSGI application which should
not be able to see them when Apache is performing authorisation. If Apache
is performing authorisation, a WSGI application can still find out what
type of authorisation scheme was used by checking the variable
``AUTH_TYPE`` of the WSGI application environment. The login name of the
authorised user can be determined by checking the variable
``REMOTE_USER``.
