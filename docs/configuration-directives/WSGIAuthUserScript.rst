==================
WSGIAuthUserScript
==================

:Description: Specify script implementing an authentication provider.
:Syntax: ``WSGIAuthUserScript`` *path* [ *options* ]
:Context: directory, .htaccess
:Override: AuthConfig

The WSGIAuthUserScript directive can be used to specify a script which
implements an Apache authentication provider.

Such an authentication provider can be used where you want Apache to worry
about the handshaking related to HTTP Basic and Digest authentication and
you only wish to deal with supplying the user credentials for authenticating
the user.

If using at least Apache 2.2, other Apache modules implementing custom
authentication mechanisms can also make use of the authentication provider
if they are using the corresponding Apache C API for accessing them.

More detailed information on using the WSGIAuthUserScript directive can be
found in :doc:`../user-guides/access-control-mechanisms`.

The options which can be supplied to the WSGIAuthUserScript directive are:

**application-group=name**
    Specifies the name of the application group within the specified
    process for which the script file will be loaded.

    If the 'application-group' option is not supplied, the special value
    '%{GLOBAL}' which denotes that the script file be loaded within the
    context of the first interpreter created by Python when it is
    initialised will be used. Otherwise, will be loaded into the
    interpreter for the specified application group.

Note that the script always runs in processes associated with embedded
mode. It is not possible to delegate the script such that it is run within
context of a daemon process.

