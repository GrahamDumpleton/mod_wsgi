==================
WSGIRestrictStdout
==================

:Description: Enable restrictions on use of STDOUT.
:Syntax: ``WSGIRestrictStdout On|Off``
:Default: ``WSGIRestrictStdout On``
:Context: server config

A well behaved Python WSGI application should never attempt to write any
data directly to ``sys.stdout`` or use the ``print`` statement without
directing it to an alternate file object. This is because ways of hosting
WSGI applications such as CGI use standard output as the mechanism for
sending the content of a response back to the web server. If a WSGI
application were to directly write to ``sys.stdout`` it could interfere
with the operation of the WSGI adapter and result in corruption of the
output stream.

In the interests of promoting portability of WSGI applications, mod_wsgi
restricts access to ``sys.stdout`` and will raise an exception if an
attempt is made to use ``sys.stdout`` explicitly.

The only time that one might want to remove this restriction is purely out
of convencience of being able to use the ``print`` statement during
debugging of an application, or if some third party module or WSGI
application was errornously using ``print`` when it shouldn't. If
restrictions on using ``sys.stdout`` are removed, any data written to
it will instead be sent through to ``sys.stderr`` and will appear in
the Apache error log file.
