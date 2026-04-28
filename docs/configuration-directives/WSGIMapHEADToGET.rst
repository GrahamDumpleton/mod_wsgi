================
WSGIMapHEADToGET
================

:Description: Enable/disable mapping of HEAD request to GET.
:Syntax: ``WSGIMapHEADToGET On|Off|Auto``
:Default: ``WSGIMapHEADToGET Auto``
:Context: server config, virtual host, directory, .htaccess

The ``WSGIMapHEADToGET`` directive controls whether ``HEAD`` requests are
automatically mapped to ``GET`` so that Apache output filters which need to
inspect the complete response body can still produce correct response
headers.

The directive accepts three values:

* ``Auto`` (the default): map ``HEAD`` to ``GET`` only when an output
  filter is registered that needs the full response body, such as
  ``mod_deflate`` or ``mod_cache``.
* ``On``: always map ``HEAD`` to ``GET``, even if no such output filter
  is registered.
* ``Off``: always preserve the original request method.

For example::

  WSGIMapHEADToGET On

The directive may be required where a WSGI application tries to optimise
and avoid doing work for a ``HEAD`` request by not actually generating a
response. By doing this the application can break Apache filters for
caching or compression, so the mapping of ``HEAD`` to ``GET`` can be
needed to avoid problems.
