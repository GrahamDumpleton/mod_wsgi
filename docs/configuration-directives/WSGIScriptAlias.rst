===============
WSGIScriptAlias
===============

:Description: Maps a URL to a filesystem location and designates the target as a WSGI script.
:Syntax: ``WSGIScriptAlias`` *URL-path file-path|directory-path*
:Context: server config, virtual host

The WSGIScriptAlias directive behaves in the same manner as the
`Alias`_ directive, except that it additionally marks the target directory
as containing WSGI scripts, or marks the specific *file-path* as a script,
that should be processed by mod_wsgi's ``wsgi-script`` handler.

Where the target is a *directory-path*, URLs with a case-sensitive
(%-decoded) path beginning with *URL-path* will be mapped to scripts
contained in the indicated directory.

For example::

  WSGIScriptAlias /wsgi-scripts/ /web/wsgi-scripts/

A request for ``http://www.example.com/wsgi-scripts/name`` in this case
would cause the server to run the WSGI application defined in
``/web/wsgi-scripts/name``. This configuration is essentially equivalent
to::

  Alias /wsgi-scripts/ /web/wsgi-scripts/
  <Location /wsgi-scripts>
  SetHandler wsgi-script
  Options +ExecCGI
  </Location>

Where the target is a *file-path*, URLs with a case-sensitive
(%-decoded) path beginning with *URL-path* will be mapped to the script
defined by the *file-path*.

For example::

  WSGIScriptAlias /name /web/wsgi-scripts/name

A request for ``http://www.example.com/name`` in this case would cause the
server to run the WSGI application defined in ``/web/wsgi-scripts/name``.

If possible you should avoid placing WSGI scripts under the `DocumentRoot`_
in order to avoid accidentally revealing their source code if the
configuration is ever changed. The WSGIScriptAlias makes this easy by
mapping a URL and designating the location of any WSGI scripts at the same
time. If you do choose to place your WSGI scripts in a directory already
accessible to clients, do not use WSGIScriptAlias. Instead, use
`<Directory>`_, `SetHandler`_ and `Options`_ as in::

  <Directory /usr/local/apache/htdocs/wsgi-scripts>
  SetHandler wsgi-script
  Options ExecCGI
  </Directory>

This is necessary since multiple *URL-paths* can map to the same filesystem
location, potentially bypassing the WSGIScriptAlias and revealing the
source code of the WSGI scripts if they are not restricted by a
`<Directory>`_ section.

.. _Alias: http://httpd.apache.org/docs/2.2/mod/mod_alias.html#alias
.. _DocumentRoot: http://httpd.apache.org/docs/2.2/mod/core.html#documentroot
.. _<Directory>: http://httpd.apache.org/docs/2.2/mod/core.html#directory
.. _SetHandler: http://httpd.apache.org/docs/2.2/mod/core.html#sethandler
.. _Options: http://httpd.apache.org/docs/2.2/mod/core.html#options
