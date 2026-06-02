===================
WSGIScriptReloading
===================

:Description: Enable/Disable detection of WSGI script file changes.
:Syntax: ``WSGIScriptReloading On|Off``
:Default: ``WSGIScriptReloading On``
:Context: server config, virtual host, directory, .htaccess
:Override: ``FileInfo``

The WSGIScriptReloading directive controls whether changes to a WSGI
script file trigger automatic reloading of the WSGI application. By
default reloading is enabled and the modification time of the WSGI
script file is checked when each request arrives.

The mechanism that runs in response to a detected change depends on
which mode the application is running in:

* In **embedded mode**, only the WSGI script file itself is reloaded.
  The script's entry in ``sys.modules`` is dropped and the file is
  re-imported in the same request that detected the change, with the
  request then served by the freshly loaded code. The Python sub
  interpreter and any other Python modules already loaded into it are
  not affected — changes to those other modules are not picked up
  until Apache is restarted.

* In **daemon mode**, the daemon process group that the application
  belongs to is gracefully restarted. In-flight requests are allowed
  to complete; new requests start serving from the freshly loaded
  process. With multiple processes in the group, only one process
  restarts at a time so the application remains available.

To disable script reloading completely::

  WSGIScriptReloading Off

Disabling reloading is appropriate when:

* You deploy by explicitly restarting Apache or signalling daemon
  process groups, and don't want a stray ``touch`` of the script file
  to trigger an unexpected reload.
* The application directory lives on a network filesystem where mtime
  values can be unreliable.
* You want to remove the per-request stat call on the script file.

Note that this directive only controls reloading triggered by changes
to the WSGI script file itself. To force an application reload without
modifying the script file, daemon process groups can be signalled
directly. See the :doc:`../user-guides/reloading-source-code` guide
for the full picture of how source-code reloading works under
mod_wsgi.
