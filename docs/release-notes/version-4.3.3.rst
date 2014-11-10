=============
Version 4.3.3
=============

Version 4.3.3 of mod_wsgi can be obtained from:

  https://github.com/GrahamDumpleton/mod_wsgi/archive/4.3.3.tar.gz

Known Issues
------------

1. The makefiles for building mod_wsgi on Windows are currently broken and
need updating. As most new changes relate to mod_wsgi daemon mode, which is
not supported under Windows, you should keep using the last available
binary for version 3.X on Windows instead.

Bugs Fixed
----------

1. When an exception occurs during the yielding of data from a generator
returned from the WSGI application, and chunked transfer encoding was used
on the response, then a '0' chunk would be errornously added at the end of
the response content even though the response was likely incomplete. The
result would be that clents wouldn't be able to properly detect that the
response was truncated due to an error. This issue is now fixed for when
embedded mode is being used. Fixing it for daemon mode is a bit trickier.

New Features
------------

1. Added new feature to ``mod_wsgi-express`` implementing timeouts on the
reading of the request, including headers, and the request body. This
feature uses the Apache module ``mod_reqtimeout`` to implement the feature.

By default a read timeout on the initial request including headers of 15
seconds is used. This can dynamically increase up to a maximum of 30
seconds if the request data is received at a minimum required rate.

By default a read timeout on the request body of 15 seconds is used. This
can dynamically increase if the request data is received at a minimum
required rate.

The options to override the defaults are ``--header-timeout``,
``--header-max-timeout``, ``--header-min-rate``, ``--body-timeout``,
``--body-max-timeout`` and ``--body-min-rate``. For a more detailed
explaination of this feature, consult the documentation for the Apache
``mod_reqtimeout`` module.
