=============
Version 4.3.0
=============

Version 4.3.0 of mod_wsgi can be obtained from:

  https://github.com/GrahamDumpleton/mod_wsgi/archive/4.3.0.tar.gz

Known Issues
------------

1. The makefiles for building mod_wsgi on Windows are currently broken and
need updating. As most new changes relate to mod_wsgi daemon mode, which is
not supported under Windows, you should keep using the last available
binary for version 3.X on Windows instead.

Bugs Fixed
----------

1. Performing authorization using the ``WSGIAuthGroupScript`` was not
working correctly on Apache 2.4 due to changes in how auth providers
and authentication/authorization works. The result could be that a user
could gain access to a resource even though they were not in the
required group.

2. Under Apache 2.4, when creating the ``environ`` dictionary for
passing into access/authentication/authorisation handlers, the behvaiour
of Apache 2.4 as it pertained to the WSGI application, whereby it
blocked the passing of any HTTP headers with a name which did not contain
just alphanumerics or '-', was not being mirrored. This created the
possibility of HTTP header spoofing in certain circumstances. Such headers
are now being ignored.

3. When ``home`` option was used with ``WSGIDaemonProcess`` directive an
empty string was added to ``sys.path``. This meant current working directory
would be searched. This was fine so long as the current working directory
wasn't changed, but if it was, it would no longer look in the home
directory. Need to use the actual home directory instead.

4. Fixed Django management command integration so would work for versions
of Django prior to 1.6 where ``BASE_DIR`` didn't exist in Django settings
module.

Features Changed
----------------

1. In Apache 2.4, any headers with a name which does not include only
alphanumerics or '-' are blocked from being passed into a WSGI application
when the CGI like WSGI ``environ`` dictionary is created. This is a
mechanism to prevent header spoofing when there are multiple headers where
the only difference is the use of non alphanumerics in a specific character
position.

This protection mechanism from Apache 2.4 is now being restrospectively
applied even when Apache 2.2 is being used and even though Apache itself
doesn't do it. This may technically result in headers that were previously
being passed, no longer being passed. The change is also technically
against what the HTTP RFC says is allowed for HTTP header names, but such
blocking would occur in Apache 2.4 anyway due to changes in Apache. It is
also understood that other web servers such as nginx also perform the same
type of blocking. Reliance on HTTP headers which use characters other
than alphanumerics and '-' is therefore dubious as many servers will now
discard them when needing to be passed into a system which requires the
headers to be passed as CGI like variables such as is the case for WSGI.

2. In Apache 2.4, only ``wsgi-group`` is allowed when using the ``Require``
directive for group authorisation. In prior Apache versions ``group`` would
also be accepted and matched by the ``wsgi`` auth provider. The inability
to use ``group`` is due to a change in Apache itself and not mod_wsgi. To
avoid any issues going forward though, the mod_wsgi code will now no longer
check for ``group`` even if for some reason Apache still decides to pass
the authorisation check off to mod_wsgi even when it shouldn't.

New Features
------------

1. The value of the ``REMOTE_USER`` variable for an authenticated user
when user ``Basic`` authentication can now be overridden from an
authentication handler specified using the ``WSGIAuthUserScript``. To
override the name used to identify the user, instead of returning ``True``
when indicating that the user is allowed, return the name to be used for
that user as a string. That value will then be passed through in
``REMOTE_USER`` in place of any original value::

    def check_password(environ, user, password):
        if user == 'spy':
            if password == 'secret':
                return 'grumpy'
            return False
        return None

2. Added the ``--debug-mode`` option to ``mod_wsgi-express`` which results
in Apache and the WSGI application being run in a single process which is
left attached to stdin/stdout of the shell where the script was run. Only a
single thread will be used to handle any requests.

This feature enables the ability to interactively debug a Python WSGI
application using the Python debugger (``pdb``). The simplest way to
break into the Python debugger is by adding to your WSGI application code::

    import pdb; pdb.set_trace()

3. Added the ``--application-type`` option to ``mod_wsgi-express``. This
defaults to ``script`` indicating that the target WSGI application provided
to ``mod_wsgi-express`` is a WSGI script file defined by a relative or
absolute file system path.

In addition to ``script``, it is also possible to supply for the application
type ``module`` and ``paste``.

For the case of ``module``, the target WSGI application will be taken to
reside in a Python module with the specified name. This module will be
loaded using the standard Python module import system and so must reside
on the Python module search path.

For the case of ``paste``, the target WSGI application will be taken to be
a Paste deployment configuration file. In loading the Paste deployment
configuration file, any WSGI application pipeline specified by the
configuration will be constructed and the resulting top level WSGI
application entry point returned used as the WSGI application.

Note that the code file for the WSGI script file, Python module, or Paste
deployment configuration file, if modified, will all result in the WSGI
application being automatically reloaded on the next web request.

4. Added the ``--auth-user-script`` and ``--auth-type`` options to
``mod_wsgi-express`` to enable the hosted site to implement user
authentication using either HTTP ``Basic`` or ``Digest`` authentication
mechanisms. The ``check_password()`` or ``get_realm_hash()`` functions
should follow the same form as if using the ``WSGIAuthUserScript`` direct
with mod_wsgi when using manual configuration.

5. Added the ``--auth-group-script`` and ``--auth-group`` options to
``mod_wsgi-express`` to enable group authorization to be performed using a
group authorization script, in conjunction with a user authentication
script. The ``groups_for_user()`` function should follow the same form as
if using the ``WSGIAuthGroupScript`` direct with mod_wsgi when using manual
configuration.

By default any users must be a member of the ``wsgi`` group. The name of
this group though can be overridden using the ``--auth-group`` option.
It is recommended that this be overridden rather than changing your own
application to use the ``wsgi`` group.

6. Added the ``--directory-index`` option to ``mod_wsgi-express`` to enable
a index resource to be added to the document root directory which would
take precedence over the WSGI application for the root page for the site.

7. Added the ``--with-php5`` option to ``mod_wsgi-express`` to enable the
concurrent hosting of a PHP web application in conjunction with the WSGI
application. Due to the limitations of PHP, this is currently only
supported if using prefork MPM.

8. Added the ``--server-name`` option to ``mod_wsgi-express``. When this is
used and set to the host name for the web site, a virtual host will be
created to ensure that the server only accepts web requests for that host
name.

If the host name starts with ``www.`` then web requests will also be
accepted against the parent domain, that is the host name without the
``www.``, but those requests will be automatically redirected to the
specified host name on the same port as that used for the original request.

When the ``--server-name`` option is being used, the ``--server-alias``
option can also be specified, multiple times if need be, to setup alternate
names for the web site on which web requests should also be accepted.
Wildcard aliases may be used in the name if wishing to match multiple
sub domains in one go.

If for some reason you do still need to be able to access the server via
``localhost`` when a virtual host for a set server name is being used, you
can supply the ``--allow-localhost`` option.

9. Added the ``--rotate-logs`` option to ``mod_wsgi-express`` to enable log
file rotation. By default the error log and access log, if enabled, will be
rotated when they reach 5MB in size. To change the size at which the log
files will be rotated, use the ``--max-log-size`` option. If the
``rotatelogs`` command is not being found properly, its location can be
specified using the ``--rotatelogs-executable`` option.

10. Added the ``--ssl-port`` and ``--ssl-certificate`` options to
``mod_wsgi-express``. When both are set, with the latter being the stub
path for the SSL certificate ``.crt`` and ``.key`` file, then HTTPS
requests will be handled over the designated SSL port.

When ``--https-only`` is supplied, any requests made over HTTP to the non
SSL port will be automatically redirected so as to use a HTTPS connection
over the SSL connection.

Note that if using the ``--allow-localhost`` option, redirection from a
HTTP to HTTPS connection will not occur when access via ``localhost``.

11. Added the ``--setenv`` option to ``mod_wsgi-express`` to enable request
specific name/value pairs to be added to the WSGI environ dictionary. The
values are restricted to string values.

Also added a companion ``--passenv`` option to ``mod_wsgi-express`` to
indicate the names of normal process environment variables which should
be added to the per request WSGI environ dictionary.

12. Added the ``WSGIMapHEADToGET`` directive for overriding the previous
behaviour of automatically mapping any ``HEAD`` request to a ``GET`` request
when an Apache output filter was registered that may want to see the complete
response in order to generate correct response headers.

The directive can be set to be either ``Auto`` (the default), ``On`` which
will always map a ``HEAD`` to ``GET`` even if no output filters detected and
``Off`` to always preserve the original request method type.

The original behaviour was to avoid problems with users trying to optimise
for ``HEAD`` requests and then breaking caching mechanisms because the
response headers for a ``HEAD`` request for a resource didn't match a ``GET``
request against the same resource as required by HTTP.

If using mod_wsgi-express, the ``--map-head-to-get`` option can be used with
the same values.

12. Added the ``--compress-responses`` option to ``mod_wsgi-express`` to
enable compression of common text based responses such as plain text, HTML,
XML, CSS and Javascript.
