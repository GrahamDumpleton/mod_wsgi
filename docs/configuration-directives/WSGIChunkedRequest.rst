==================
WSGIChunkedRequest
==================

:Description: Enabled support for chunked request content.
:Syntax: ``WSGIChunkedRequest On|Off``
:Default: ``WSGIChunkedRequest Off``
:Context: server config, virtual host, directory, .htaccess

The WSGIChunkedRequest directive can be used to enable support for chunked
request content. Rather than Apache rejecting a request using chunked
request content, it will be allowed to pass through.

Do note however that WSGI is technically incapable of supporting chunked
request content without all chunked request content having to be first read
in and buffered. This is because WSGI requires ``CONTENT_LENGTH`` be set
when there is any request content.

In mod_wsgi no buffering is done. Thus, to be able to read the request
content in the case of a chunked transfer encoding, you need to step
outside of the WSGI specification and do things it says you aren't meant to.

You have two choices for how you can do this. The first choice you have
is to call ``read()`` on ``wsgi.input`` but not supply any argument at all.
This will cause all request content to be read in and returned.

The second is to loop on calling ``read()`` on ``wsgi.input`` with a set
block size passed as argument and do this until ``read()`` returns an empty
string.

Because both calling methods are not allowed under WSGI specification, in
using these, your code will not technically be portable to other WSGI hosting
mechanisms, although if those other WSGI servers support it, you will be
okay.

That all said, although technically not permitted by the WSGI specification,
some WSGI frameworks do now incoporate support for handling chunked request
content, as well as where compressed request content is expanded by the web
server such that ``CONTENT_LENGTH`` is no longer accurate. The required
behaviour is enabled in these frameworks by the WSGI server passing through
the non standard ``wsgi.input_terminated`` key set as ``True`` in the per
request WSGI ``environ`` dictionary. When this is done the web frameworks
will always read all available input and ignore ``CONTENT_LENGTH``.

Because mod_wsgi guarantees that an empty string is returned when all input
is exhausted, it will always set this flag.

It is known that Flask/Werkzeug supports the ``wsgi.input_terminated`` flag.
