=============
Version 4.3.3
=============

Version 4.3.3 of mod_wsgi can be obtained from:

  https://codeload.github.com/GrahamDumpleton/mod_wsgi/tar.gz/4.3.3

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

2. Response headers returned from the WSGI application running in daemon
mode were being wrongly attached to the internal Apache data structure for
``err_headers_out`` instead of ``headers_out``. This meant that the
``Header`` directive of the ``mod_headers`` module, with its default
condition of only checking ``onsuccess`` headers would not work as
expected.

In order to be able to check for or modify the response headers one would
have had to use the ``Header`` directive with the ``always`` condition and
if also working with an embedded WSGI application, also define a parallel
``Header`` directive but with the ``onsuccess`` condition.

For daemon mode, response headers will now be correctly associated with
``headers_out`` and the ``onsuccess`` condition of the ``Header`` directive.
The only exception to this in either embedded or daemon mode now is that
of the ``WWW-Authenticate`` header, which remains associated with
``err_headers_out`` so that the header will survive an internal redirect
such as to an ``ErrorDocument``.

3. When optional support for chunked requests was enabled, it was only
working properly for embedded mode. The feature now also works properly for
daemon mode.

The directive to enable support for chunked request content is
``WSGIChunkedRequest``. The command line option when using mod_wsgi express
is ``--chunked-request``.

This is an optional feature, as the WSGI specification is arguably broken
in not catering properly for mutating input filters or chunked request
content. Support for chunked request content could be enabled by default,
but then WSGI applications which don't simply read all available content
and instead rely entirely on ``CONTENT_LENGTH``, would likely see a chunked
request as having no content at all, as it would interpret the lack of
the ``CONTENT_LENGTH`` as meaning the length of the content is zero.

An attempt to get the WSGI specification ammended to be more sensible and
allow what is a growing requirement to support chunked request content was
ignored. Thus support is optional. You will need to enable this if you wish
to rely on features of any WSGI framework that take the more sensible
approach of ignoring ``CONTENT_LENGTH`` as a true indicator of content
length. One such WSGI framework which provides some support for chunked
request content is Flask/Werkzeug. Check its documentation or the code for
Flask/Werkzeug to to see if any additional ``SetEnv`` directive may be
required to enable the support in Flask/Werkzeug.

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

4. Error messages and exceptions raised when there is a failure to read
request content, or write back a response now provide the internal error
indication from Apache as to why. For the ``IOError`` exceptions which are
raised, that the exception originates within Apache/mod_wsgi is now flagged
in the description associated with the exception.
