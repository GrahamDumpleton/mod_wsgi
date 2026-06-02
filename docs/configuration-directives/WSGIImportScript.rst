================
WSGIImportScript
================

:Description: Specify a script file to be loaded on process start.
:Syntax: ``WSGIImportScript`` *path* ``[`` *options* ``]``
:Context: server config

The WSGIImportScript directive can be used to specify a script file to be
loaded when a process starts. Options must be provided to indicate the name
of the process group and the application group into which the script will
be loaded.

For example, to preload a script into a daemon process group called
``mygroup``, using the main Python interpreter::

  WSGIDaemonProcess mygroup processes=2 threads=15
  WSGIImportScript /web/wsgi-scripts/myapp.wsgi \
      process-group=mygroup application-group=%{GLOBAL}

The options which must supplied to the WSGIImportScript directive are:

**process-group=name**
    Specifies the name of the process group for which the script file will
    be loaded.

    The name of the process group can be set to the special value
    '%{GLOBAL}' which denotes that the script file be loaded for the Apache
    child processes. Any other value names a daemon mode process group
    set up using the WSGIDaemonProcess directive.

**application-group=name**
    Specifies the name of the application group within the specified
    process for which the script file will be loaded.

    The name of the application group can be set to the special value
    '%{GLOBAL}' which denotes that the script file be loaded within the
    context of the main Python interpreter. Otherwise, will be loaded
    into the sub interpreter for the specified application group.

Because the script files are loaded prior to beginning to accept any
requests, any delay in loading the script will not cause actual requests to
be blocked. As such, the WSGIImportScript can be used to preload a WSGI
application script file on process start so that it is ready when actual
user requests arrive. For where there are multiple processes handling
requests, this can reduce or eliminate the apparent stalling of an
application when performing a restart of Apache or a daemon mode process
group.

For most setups the same effect can be obtained more concisely by
supplying both ``process-group`` and ``application-group`` options to
the WSGIScriptAlias directive, which auto-preloads the script.
WSGIImportScript is the appropriate choice when the WSGI application
isn't being mounted via WSGIScriptAlias (for example, configurations
that use ``SetHandler wsgi-script`` directly), or when additional
script files need to be preloaded into the same process group
alongside the main one.
