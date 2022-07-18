==================
WSGITrustedProxies
==================

:Description: Specify a list of trusted proxies.
:Syntax: ``WSGITrustedProxies`` *ipaddr|(ipaddr-1 ipaddr-2 ...)*
:Context: server config, virtual host, directory, .htaccess
:Override: ``FileInfo``

Used to specify a list of IP addresses for proxies placed in front of the
Apache instance which are trusted.

This directive only has effect when used in conjunction with the
``WSGITrustedProxyHeaders`` directive. For more details see the documentation
for the ``WSGITrustedProxyHeaders`` directive.
