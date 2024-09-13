==================
WSGIMapHEADToGET
==================

:Description: Enable/disable mapping of HEAD request to GET.
:Syntax: ``WSGIMapHEADToGET On|Off|Auto``
:Default: ``WSGIMapHEADToGET Auto``
:Context: server config, virtual host, directory, .htaccess

The ``WSGIMapHEADToGET`` directive controls the behaviour of automatically
mapping any ``HEAD`` request to a ``GET`` request when an Apache output filter
is registered that may want to see the complete response in order to generate
correct response headers.

The directive can be set to be either ``Auto`` (the default), ``On`` which
will always map a ``HEAD`` to ``GET`` even if no output filters detected and
``Off`` to always preserve the original request method type.

The directive may be required where a WSGI application tries to optimize and
avoid doing work for a ``HEAD`` request by not actually generating a response
so that complete response headers can still be generated. By doing this the
WSGI application can break Apache filters for caching, so the mapping of
``HEAD`` to ``GET`` can be required to avoid problems.
