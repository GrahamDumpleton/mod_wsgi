=================
WSGIRestrictStdin
=================

:Description: Enable restrictions on use of STDIN.
:Syntax: ``WSGIRestrictStdin On|Off``
:Default: ``WSGIRestrictStdin Off``
:Context: server config

A well behaved Python WSGI application should never attempt to read any
input directly from ``sys.stdin``. This is because ways of hosting WSGI
applications such as CGI use standard input as the mechanism for receiving
the content of a request from the web server. If a WSGI application were to
directly read from ``sys.stdin`` it could interfere with the operation of
the WSGI adapter and result in corruption of the input stream.

When this directive is set to ``On``, mod_wsgi replaces ``sys.stdin``
with a restricted object that will raise an exception if an attempt is
made to use it. This restriction is off by default since mod_wsgi 3.0,
as the original intent of promoting portable WSGI code proved
ineffective in practice.
