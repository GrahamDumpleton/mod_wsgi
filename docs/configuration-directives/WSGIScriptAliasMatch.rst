====================
WSGIScriptAliasMatch
====================

:Description: Maps a URL to a filesystem location and designates the target as a WSGI script.
:Syntax: ``WSGIScriptAliasMatch`` *regex file-path|directory-path* ``[`` *options* ``]``
:Context: server config, virtual host

This directive is similar to the WSGIScriptAlias directive, but makes use
of regular expressions, instead of simple prefix matching. The supplied
regular expression is matched against the URL-path, and if it matches, the
server will substitute any parenthesized matches into the given string and
use it as a filename.

For example, to map a URL to scripts contained within
a directory where the script files use the ``.wsgi`` extension, but it
is desired that the extension not appear in the URL, use::

  WSGIScriptAliasMatch ^/wsgi-scripts/([^/]+) /web/wsgi-scripts/$1.wsgi

Note that you should only use WSGIScriptAliasMatch if you know what you are
doing. In most cases you should be using WSGIScriptAlias instead. If you
use WSGIScriptAliasMatch and don't do things the correct way, then you risk
modifying the value of SCRIPT_NAME as passed to the WSGI application and
this can stuff things up badly causing URL mapping to not work correctly
within the WSGI application or stuff up reconstruction of the full URL when
doing redirects. This is because the substitution of the matched sub
pattern from the left hand side back into the right hand side is often
critical.

If you think you need to use WSGIScriptAliasMatch, you probably don't
really. If you really really think you need it, then check on the mod_wsgi
mailing list about how to use it properly.

Options which can be supplied to the ``WSGIScriptAlias`` directive are:

**process-group=name**
    Defines which process group the WSGI application will be executed
    in. All WSGI applications within the same process group will execute
    within the context of the same group of daemon processes.

    If the name is set to be ``%{GLOBAL}`` the process group name will
    be set to the empty string. Any WSGI applications in the global
    process group will always be executed within the context of the
    standard Apache child processes. Such WSGI applications will incur
    the least runtime overhead, however, they will share the same
    process space with other Apache modules such as PHP, as well as the
    process being used to serve up static file content. Running WSGI
    applications within the standard Apache child processes will also
    mean the application will run as the user that Apache would normally
    run as.

**application-group=name**
    Defines which application group a WSGI application or set of WSGI
    applications belongs to. All WSGI applications within the same
    application group will execute within the context of the same Python
    sub interpreter of the process handling the request.

    If the name is set to be ``%{GLOBAL}`` the application group will be
    set to the empty string. Any WSGI applications in the global
    application group will always be executed within the context of the
    first interpreter created by Python when it is initialised, of the
    process handling the request. Forcing a WSGI application to run within
    the first interpreter can be necessary when a third party C extension
    module for Python has used the simplified threading API for
    manipulation of the Python GIL and thus will not run correctly within
    any additional sub interpreters created by Python.

If both ``process-group`` and ``application-group`` options are set, and
the WSGI script file doesn't include substiutions values to be supplied
from the matched URL pattern, the WSGI script file will be pre-loaded when
the process it is to run in is started, rather than being lazily loaded on
the first request.
