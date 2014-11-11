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

2. Added a new ``%{HOST}`` label that can be used when specifying the
application group (Python sub interpreter context) to run the WSGI
application in, via the ``WSGIApplicationGroup`` directive, or the
``application-group`` option to ``WSGIScriptAlias``.

This new label will result in an application group being used with a name
that corresponds to the name of the site as identified by the HTTP request
``Host`` header. Where the accepting port number is other than 80 or 443,
then the name of the application group will be suffixed with the port
number separated by a colon.

Note that extreme care must be exercised when using this new label to
specify the application group. This is because the HTTP request ``Host``
header is under the control of the user of the site.

As such, it should only be used in conjunction with a configuration which
adequately blocks access to anything but the expected hosts.

For example, it would be dangerous to use this inside of a ``VirtualHost``
where the ``ServerAlias`` directive is used with a wildcard. This is
because a user could pick arbitrary host names matching the wildcard and so
force a new sub interpreter context to be created each time and so blow out
memory usage.

Similarly, caution should be exercised with ``mod_vhost_alias``, with any
configuration forbidding any host which doesn't specifically match some
specified resource such as a directory.

Finally, this should probably never be used when not using either
``VirtualHost`` or ``mod_vhost_alias`` as in that case the server is likely
going to accept any ``Host`` header value without exclusions.

3. Allow ``%{RESOURCE}``, ``%{SERVER}`` and ``%{HOST}`` labels to be used
with the ``WSGIProcessGroup`` directive, or the ``process-group`` option of
the ``WSGIScriptAlias`` directive.

For this to work, it is still necessary to have setup an appropriate
mod_wsgi daemon process group using the ``WSGIDaemonProcess`` directive,
with name that will match the expanded value for the respective labels.
If there is no matching mod_wsgi daemon process group specified, then
a generic HTTP 500 internal server error response would be returned and
the reason, lack of matching mod_wsgi daemon process group, being logged in
the Apache error log.
