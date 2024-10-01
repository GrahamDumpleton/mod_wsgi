=================
WSGIErrorOverride
=================

:Description: Enable/disable use of Apache error documents.
:Syntax: ``WSGIErrorOverride On|Off``
:Default: ``WSGIErrorOverride Off``
:Context: server config, virtual host, directory, .htaccess

The ``WSGIErrorOverride`` directive when set to ``On``, and the WSGI application
is running in daemon mode, will result in Apache error documents being used
rather than those passed back by the WSGI application. This allows error
documents to match any web site that the WSGI application may be integrated as a
part of. This feature is akin to the ``ProxyErrorOverride`` directive of Apache
but for mod_wsgi only.

Note that this directive has no effect when the WSGI application is running in
embedded mode.
