=======================
WSGITrustedProxyHeaders
=======================

:Description: Specify a list of trusted proxy headers.
:Syntax: ``WSGITrustedProxyHeaders`` *header|(header-1 header-2 ...)*
:Context: server config, virtual host, directory, .htaccess
:Override: ``FileInfo``

When trusted proxies are designated, this is used to specify the headers
which are used to convey information from a proxy to a web server behind the
proxy that are to be trusted.

The IP addresses of the proxies to be trusted should be specified using the
``WSGITrustedProxies`` directive.

As there are multiple conventions for what headers are used to convey
information from the proxy to the web server you need to specify the specific
header from a supported list of headers for a particular purpose that you want
to trust using the ``WSGITrustedProxyHeaders`` directive.

When a request is then received from a trusted proxy, only the header from
the set of headers for that particular purpose is passed through to the WSGI
application and all others will be dropped. If a request was instead from an
IP address which isn't a trusted proxy, then all headers in that set of headers
will be dropped and not passed through.

Depending on the purpose of the header, modifications will be made to other
special variables passed through to the WSGI application. It is these other
variables which is what the WSGI application should consult and the original
header should never be consulted, with it only being provided as an indication
of which header was used to set the special variable.

The different sets of supported headers used by proxies are as follows.

For passing through the IP address of the remote HTTP client the supported
headers are:

* X-Forwarded-For
* X-Client-IP
* X-Real-IP

You should select only one of these headers as the authoritative source for
the IP address of the remote HTTP client as sent by the proxy. Never select
multiple headers because if you do which will be used is indeterminate.

The de-facto standard for this type of header is ``X-Forwarded-For`` and it
is recommended that it be used if your proxy supports it.

The configuration might therefore be::

    WSGITrustedProxies 1.2.3.4
    WSGITrustedProxyHeaders X-Forwarded-For

With this configuration, when a request is received from the trusted proxy only
the ``X-Forwarded-For`` header will be passed through to the WSGI application.
This will be done following CGI convention as used by WSGI, namely in the
``HTTP_X_FORWARDED_FOR`` variable.

For this set of headers, the ``REMOTE_ADDR`` CGI variable as used by WSGI will
be modified and set to the IP address of the remote HTTP client. A WSGI
application in this case should always use ``REMOTE_ADDR`` and never consult
the original header files.

For passing through the protocol of the original request received by the
trusted proxy the supported headers are:

* X-Forwarded-HTTPS
* X-Forwarded-Proto
* X-Forwarded-Scheme
* X-Forwarded-SSL
* X-HTTPS
* X-Scheme

You should select only one of these headers as the authoritative source for what
protocol was used by the remote HTTP client as sent by the proxy. Never select
multiple headers because if you do which will be used is indeterminate.

The de-facto standard for this type of header is ``X-Forwarded-Proto`` and it
is recommended that it be used if your proxy supports it.

The configuration might therefore be::

    WSGITrustedProxies 1.2.3.4
    WSGITrustedProxyHeaders X-Forwarded-Proto

With this configuration, when a request is received from the trusted proxy only
the ``X-Forwarded-Proto`` header will be passed through to the WSGI application.
This will be done following CGI convention as used by WSGI, namely in the
``HTTP_X_FORWARDED_PROTO`` variable.

For this set of headers, the ``wsgi.url_scheme`` variable passed to the WSGI
application will be modified to indicate whether the original request used the
``https`` protocol. Note that although it is a convention when using CGI
scripts with Apache, the mod_wsgi module removes the ``HTTPS`` variable from
the set of variables passed to the WSGI application. You should always use
the ``wsgi.url_scheme`` variable in a WSGI application.

For passing through the host name targeted by the original request received by
the trusted proxy the supported headers are:

* X-Forwarded-Host
* X-Host

You should select only one of these headers as the authoritative source for the
host targeted by the original request as sent by the proxy. Never select
multiple headers because if you do which will be used is indeterminate.

The de-facto standard for this type of header is ``X-Forwarded-Host`` and it
is recommended that it be used if your proxy supports it.

The configuration might therefore be::

    WSGITrustedProxies 1.2.3.4
    WSGITrustedProxyHeaders X-Forwarded-Host

With this configuration, when a request is received from the trusted proxy only
the ``X-Forwarded-Host`` header will be passed through to the WSGI application.
This will be done following CGI convention as used by WSGI, namely in the
``HTTP_X_FORWARDED_HOST`` variable.

For this set of headers, the ``HTTP_HOST`` variable passed to the WSGI
application will be overridden with the value from the header supplied by the
proxy. That is, the value from the proxy for the original request will even
override any explicit ``Host`` header supplied in the request from the proxy,
which in normal cases would be the host of the web server. A WSGI application
should always consult the ``HTTP_HOST`` variable and not the separate header
supplied by the proxy.

For passing through the port targeted by the original request received by the
trusted proxy, the only supported header is:

* X-Forwarded-Port

Although it is the only supported header, you still must select if as a trusted
header to have it processed in the same way as other trusted headers.

The configuration might therefore be::

    WSGITrustedProxies 1.2.3.4
    WSGITrustedProxyHeaders X-Forwarded-Port

With this configuration, when a request is received from the trusted proxy only
the ``X-Forwarded-Port`` header will be passed through to the WSGI application.
This will be done following CGI convention as used by WSGI, namely in the
``HTTP_X_FORWARDED_PORT`` variable.

For this header, the ``SERVER_PORT`` variable passed to the WSGI application
will be overridden with the value from the header supplied by the proxy. A WSGI
application should always consult the ``SERVER_PORT`` variable and not the
separate header supplied by the proxy.

For passing through the host name of any proxy, to use in overriding the host
name of the web server, the only supported header is:

* X-Forwarded-Server

Although it is the only supported header, you still must select if as a trusted
header to have it processed in the same way as other trusted headers.

The configuration might therefore be::

    WSGITrustedProxies 1.2.3.4
    WSGITrustedProxyHeaders X-Forwarded-Server

With this configuration, when a request is received from the trusted proxy only
the ``X-Forwarded-Server`` header will be passed through to the WSGI application.
This will be done following CGI convention as used by WSGI, namely in the
``HTTP_X_FORWARDED_SERVER`` variable.

For this header, the ``SERVER_NAME`` variable passed to the WSGI application
will be overridden with the value from the header supplied by the proxy. A WSGI
application should always consult the ``SERVER_NAME`` variable and not the
separate header supplied by the proxy.

For passing through the apparent URL sub path of a web application, as mapped
by the trusted proxy, the supported headers are:

* X-Script-Name
* X-Forwarded-Script-Name

You should select only one of these headers as the authoritative source for the
host targeted by the original request as sent by the proxy. Never select
multiple headers because if you do which will be used is indeterminate.

The configuration might therefore be::

    WSGITrustedProxies 1.2.3.4
    WSGITrustedProxyHeaders X-Script-Name

With this configuration, when a request is received from the trusted proxy only
the ``X-Script-Name`` header will be passed through to the WSGI application.
This will be done following CGI convention as used by WSGI, namely in the
``HTTP_X_SCRIPT_NAME`` variable.

For this header, the ``SCRIPT_NAME`` variable passed to the WSGI application
will be overridden with the value from the header supplied by the proxy. A WSGI
application should always consult the ``SCRIPT_NAME`` variable and not the
separate header supplied by the proxy.

Examples above show using a single header of a specific purpose at one time.
When you need to trust multiple headers for different purposes, you can list
them separated by spaces using one instance of ``WSGITrustedProxyHeaders``::

    WSGITrustedProxyHeaders X-Forwarded-For X-Forwarded-Host X-Forwarded-Port

or in separate directives::

    WSGITrustedProxyHeaders X-Forwarded-For
    WSGITrustedProxyHeaders X-Forwarded-Host
    WSGITrustedProxyHeaders X-Forwarded-Port

As already highlighted you should only list one header for a specific purpose
when there are multiple conventions for what header to use. Which you use will
depend on the configuration of your proxy. You should only trust headers which
are always set by the proxy, never trust headers which are optionally set by
proxies because if not overridden by a proxy, a remote client could still
supply the header.

Also remember that in general you should not consult the proxied headers
themselves, but instead consult the special variables set from those headers
which are passed to the WSGI application and which are defined as being special
to WSGI. As illustration of how such special variables are used, consider
for example the notes in the WSGI specification around URL reconstruction.

* https://peps.python.org/pep-3333/#url-reconstruction

Finally, if using this feature to trust proxies and designated headers, do not
enable in any WSGI framework or application separate functionality it may have
for also processing the proxy headers. You should only rely on what mod_wsgi
has done to update variables special to WSGI.
