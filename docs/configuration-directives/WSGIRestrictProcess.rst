===================
WSGIRestrictProcess
===================

:Description: Restrict which daemon process groups can be selected.
:Syntax: ``WSGIRestrictProcess`` *group-1 group-2 ...*
:Syntax: WSGIRestrictProcess *group-1 group-2 ...*
:Context: server config, virtual host, directory

When using the WSGIProcessGroup directive, daemon process groups defined
within virtual hosts with the same server name, or those defined at global
scope outside of any virtual hosts can be selected. It is not possible to
select a daemon process group which is defined within a different virtual
host.

To further limit which of the available daemon process groups can be
selected, the WSGIRestrictProcess directive can be used to list a
restricted set of daemon process group names. This could be used for
example where %{ENV} substitution is being used to allow the daemon process
group to be selected from a .htaccess file for a specific user.

The main Apache configuration for this scenario might be::

  WSGIDaemonProcess default processes=2 threads=25

  <VirtualHost *:80>
  ServerName www.site.com

  WSGIDaemonProcess bob:1 user=bob group=bob threads=25
  WSGIDaemonProcess bob:2 user=bob group=bob threads=25
  WSGIDaemonProcess bob:3 user=bob group=bob threads=25

  WSGIDaemonProcess joe:1 user=joe group=joe threads=25
  WSGIDaemonProcess joe:2 user=joe group=joe threads=25
  WSGIDaemonProcess joe:3 user=joe group=joe threads=25

  SetEnv PROCESS_GROUP default
  WSGIProcessGroup %{ENV:PROCESS_GROUP}

  <Directory /home/bob/public_html>
  Options ExecCGI
  AllowOverride FileInfo
  AddHandler wsgi-script .wsgi
  WSGIRestrictProcess bob:1 bob:2 bob:3
  SetEnv PROCESS_GROUP bob:1
  </Directory>
  </VirtualHost>

The .htaccess file within the users account could then delegate specific
WSGI applications to different daemon process groups using the
`SetEnv`_ directive::

  <Files blog.wsgi>
  SetEnv PROCESS_GROUP bob:2
  </Files>

  <Files wiki.wsgi>
  SetEnv PROCESS_GROUP bob:3
  </Files>

Note that the WSGIDaemonProcess directive and corresponding features are
not available on Windows or when running Apache 1.3.

.. _SetEnv: http://httpd.apache.org/docs/2.2/mod/mod_env.html#setenv
