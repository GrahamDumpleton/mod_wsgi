==================
WSGIRestrictStdout
==================

:Description: Enable restrictions on use of STDOUT.
:Syntax: ``WSGIRestrictStdout On|Off``
:Default: ``WSGIRestrictStdout Off``
:Context: server config

A well behaved Python WSGI application should never attempt to write any
data directly to ``sys.stdout`` or use the ``print`` statement without
directing it to an alternate file object. This is because ways of hosting
WSGI applications such as CGI use standard output as the mechanism for
sending the content of a response back to the web server. If a WSGI
application were to directly write to ``sys.stdout`` it could interfere
with the operation of the WSGI adapter and result in corruption of the
output stream.

When this directive is set to ``On``, mod_wsgi replaces ``sys.stdout``
with a restricted object that will raise an exception if an attempt is
made to use it. This restriction is off by default since mod_wsgi 3.0,
as the original intent of promoting portable WSGI code proved
ineffective in practice. When the restriction is off, any data written
to ``sys.stdout`` will instead be directed to the Apache error log.
