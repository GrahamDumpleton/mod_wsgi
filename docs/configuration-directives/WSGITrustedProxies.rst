==================
WSGITrustedProxies
==================

:Description: Specify a list of trusted proxies.
:Syntax: ``WSGITrustedProxies`` *address|(address-1 address-2 ...)*
:Context: server config, virtual host, directory, .htaccess
:Override: ``FileInfo``

Used to specify the IP addresses of proxies placed in front of the Apache
instance whose forwarding headers should be honoured. When a request
arrives from a peer in this list, the headers named by
``WSGITrustedProxyHeaders`` are used to recover the original client
information (remote address, scheme, host, etc.) instead of the
peer-level connection details.

Each entry may be a single IP address or a CIDR range::

  WSGITrustedProxies 10.0.0.5 192.168.0.0/16

This directive only has effect when used in conjunction with the
``WSGITrustedProxyHeaders`` directive. For more details see the documentation
for the ``WSGITrustedProxyHeaders`` directive.

For an end-to-end walkthrough including the matching front-end proxy
configuration, see :doc:`../user-guides/running-behind-a-reverse-proxy`.
