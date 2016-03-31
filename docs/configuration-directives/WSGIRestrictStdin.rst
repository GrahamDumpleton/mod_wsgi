=================
WSGIRestrictStdin
=================

:Description: Enable restrictions on use of STDIN.
:Syntax: ``WSGIRestrictStdin On|Off``
:Default: ``WSGIRestrictStdin On``
:Context: server config

A well behaved Python WSGI application should never attempt to read any
input directly from ``sys.stdin``. This is because ways of hosting WSGI
applications such as CGI use standard input as the mechanism for receiving
the content of a request from the web server. If a WSGI application were to
directly read from ``sys.stdin`` it could interfere with the operation of
the WSGI adapter and result in corruption of the input stream.

In the interests of promoting portability of WSGI applications, mod_wsgi
restricts access to ``sys.stdin`` and will raise an exception if an
attempt is made to use ``sys.stdin`` explicitly.

The only time that one might want to remove this restriction is if the Apache
web server is being run in debug or single process mode for the purposes of
being able to run an interactive Python debugger such as ``pdb``.
