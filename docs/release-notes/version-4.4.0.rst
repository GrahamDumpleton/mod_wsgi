=============
Version 4.4.0
=============

Version 4.4.0 of mod_wsgi can be obtained from:

  https://codeload.github.com/GrahamDumpleton/mod_wsgi/tar.gz/4.4.0

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

4. Fixed a potential request content data corruption issue when running a
WSGI application in daemon mode. The bug in the code is quite obvious, yet
unable to trigger it on older mod_wsgi versions. It was though triggering
quite easily in the current release on MacOS X, prior to it being fixed,
due to the changes made to support chunked request content for daemon
processes.

Suspect it is still a latent bug in older mod_wsgi versions, but the
conditions under which it would trigger must have been harder to induce.
The lack of reported problems may have been aided by virtue of Linux UNIX
socket buffer size being quite large, in comparison to MacOS X, and so
harder to create a condition where not all data could be written onto the
UNIX socket in one call. Yet, when buffer sizes for the UNIX socket on
MacOS X were increased, it was still possible to induce the bug.

5. When the ``--working-directory`` option for ``mod_wsgi-express`` was
given a relative path name, that wasn't being translated to an absolute
path name when substituting the ``home`` option of ``WSGIDaemonProcess``
causing server startup to fail.

6. When using ``--debug-mode`` of ``mod_wsgi-express`` the working
directory for the application was not being added to ``sys.path``. This
meant that if the WSGI script was referenced from a different directory,
any module imports for other modules in that directory would fail.

Features Changed
----------------

1. Until recently, a failed attempt to change the working directory for a
daemon process to the user the process runs as would be ignored. Now it
will cause a hard failure that will prevent the daemon process from
starting. This would cause issues where the user, usually the default
Apache user, has not valid home directory. Now what will happens is that
any attempt will only be made to change the working directory to the home
directory of the user the daemon process runs as, if the 'user' option had
been explicitly set to define the user and the user is different to the
user that Apache child worker processes run as. In other words, is
different to the default Apache user.

2. The support for the ``wdb`` debugger was removed. Decided that it wasn't
mainstream enough and not ideal that still required a separate service and
port to handle debugging sessions.

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

5. When using mod_wsgi daemon mode and there is a timeout when reading
request content in order to proxy it to the daemon process, a 408 request
timeout HTTP response is now returned where as previously a generic 500
internal server error HTTP response was returned.

Note that this doesn't mean that the WSGI application wasn't actually run.
The WSGI application in the daemon process would have run as soon as the
headers had been received.

If the WSGI application had actually attempted to read the request content,
it should also have eventually received an exception of type ``IOError``
when accessing ``wsgi.input`` to read the request content, due to a
timeout or due to the proxy connection being closed before all request
content was able to be read.

If the WSGI application wasn't expecting any request content and had
ignored it, even though some was present, it would still have run to
completion and generated a response, but because the Apache child worker
process was blocked waiting for content, when the timeout occurred the
client would get the 408 HTTP response rather than the actual response
generated by the WSGI application.

6. Added the ``--log-to-terminal`` option to ``mod_wsgi-express`` to allow
the error log output to be directed to standard error for the controlling
terminal, and the access log output, if enabled, to be directed to standard
output. Similarly, the startup log output, if enabled, will be sent to
standard error also.

This should not be used in conjunction with ``--setup-only`` option when
using the generated ``apachectl`` script, unless the ``-DFOREGROUND``
option is also being supplied to ``apachectl`` at the time it is run with
the ``start`` command.

7. Added the ``--access-log-format`` option to ``mod_wsgi-express``. By
default if the access log is enabled, entries will follow the 'common' log
format as typically used by Apache. You have two options of how you can use
the ``--access-log-format``. The first is to give it the argument
'combined', which will then cause it to use this alternate log format
which is again often used with Apache. The other is to specify the log
format string yourself.

The format string can contain format string components as would be used
with the ``LogFormat`` directive. For example, to specify the equivalent to
the 'common' log format, you could use::

    --access-log-format "%h %l %u %t \"%r\" %>s %b"

This 'common' log format is identified via a nickname in the same way
'combined' is, so if you did have to specify it explicitly for some reason,
you could just have instead used::

    --access-log-format common

8. Added the ``--newrelic-config-file`` and ``--newrelic-environment``
options to ``mod_wsgi-express``. This allows these to be set using command
line options rather than requiring the New Relic environment variables.
Importantly, when the options are used, the values will be embedded in the
generated files if using ``--setup-only``. Thus they will still be set when
later using the ``apachectl`` control script to start the server.

Note that when these options are used, they will cause the equivalent New
Relic environment variable for that option to be ignored, both if running
the server immediately, or if using ``--setup-only`` and running the server
later using ``apachectl``.

9. Added the ``--enable-debugger`` option to ``mod_wsgi-express``. When
specified and at the same time the ``--debug-mode`` option is specified,
then when an exception is raised from the initial execution of the WSGI
application, when consuming the response iterable, or when calling any
``close()`` method of the response iterable, then post mortem debugging of
the exception will be triggered. Post mortem debugging is performed using
the Python debugger (pdb).

10. Added the ``--enable-coverage`` option to ``mod_wsgi-express``. When
specified and at the same time the ``--debug-mode`` option is specified,
then coverage analysis is enabled. When the server is exited, then the HTML
reports will be output to the ``htmlcov`` directory under the server
working directory, or the directory specified using the
``--coverage-directory`` option. The ``coverage`` module must be installed
for this feature to work.

11. Added the ``--enable-profiler`` option to ``mod_wsgi-express``. When
specified and at the same time the ``--debug-mode`` option is specified,
then coverage analysis is enabled. When the server is exited, then the
profiler data will be output to the ``pstats.dat`` file under the server
working directory, or the file specified using the ``--profiler-output-file``
option.

12. Added the ``--python-path`` option to ``mod_wsgi-express`` to specify
additional directories that should be added to the Python module search path.

Note that these directories will not be processed for ``.pth`` files. If
processing of ``.pth`` files is required, then the ``PYTHONPATH`` environment
variable should be set and exported in a script file referred to using the
``--envvars-script`` option.
