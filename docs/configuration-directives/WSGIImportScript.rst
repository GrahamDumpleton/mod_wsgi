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

The options which must supplied to the WSGIImportScript directive are:

**process-group=name**
    Specifies the name of the process group for which the script file will
    be loaded.
    
    The name of the process group can be set to the special value
    '%{GLOBAL}' which denotes that the script file be loaded for the Apache
    child processes. Any other value indicates appropriate process group
    for mod_wsgi daemon mode.

**application-group=name**
    Specifies the name of the application group within the specified
    process for which the script file will be loaded.

    The name of the application group can be set to the special value
    '%{GLOBAL}' which denotes that the script file be loaded within the
    context of the first interpreter created by Python when it is
    initialised. Otherwise, will be loaded into the interpreter for the
    specified application group.

Because the script files are loaded prior to beginning to accept any
requests, any delay in loading the script will not cause actual requests to
be blocked. As such, the WSGIImportScript can be used to preload a WSGI
application script file on process start so that it is ready when actual
user requests arrive. For where there are multiple processes handling
requests, this can reduce or eliminate the apparent stalling of an
application when performing a restart of Apache or a daemon mode process
group.
