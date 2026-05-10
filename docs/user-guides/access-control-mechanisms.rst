Access Control Mechanisms
=========================

This document contains information about mechanisms available in mod_wsgi
for controlling who can access a WSGI application. This includes coverage
of support for HTTP Basic and Digest authentication mechanisms, as well
as server side mechanisms for authorisation and host access control.

HTTP User Authentication
------------------------

The HTTP protocol supports user authentication mechanisms for clients
through the 'Authorization' header. The two main examples for this are
the Basic and Digest authentication mechanisms.

Unlike other HTTP headers, the authorisation header is not passed through
to a WSGI application by default. This is the case as doing so could leak
information about passwords through to a WSGI application which should not
be able to see them when Apache is performing authentication.

If Apache is performing authentication, a WSGI application can still find
out what type of authentication scheme was used by checking the variable
``AUTH_TYPE`` of the WSGI application environment. The login name of the
authorised user can be determined by checking the variable
``REMOTE_USER``.

If it is desired that the WSGI application be responsible for handling user
authentication, then it is necessary to explicitly configure mod_wsgi to
pass the required headers through to the application. This can be done by
specifying the WSGIPassAuthorization directive in the appropriate context
and setting it to 'On'.

When passing of authorisation information is enabled, the authorisation
headers are passed through to a WSGI application in the
``HTTP_AUTHORIZATION`` variable of the WSGI application environment when
the equivalent HTTP request header is present. You will still need to
provide your own code to process the header and perform the required hand
shaking with the client to indicate whether the client is permitted access.

Reflecting Application Level Authentication Back to Apache
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

When a WSGI application performs its own authentication, the result is
visible only inside the application. Apache itself does not know who the
request was authenticated as, so ``r->user`` and ``r->ap_auth_type`` remain
unset. The practical consequences are:

* The ``%u`` placeholder in ``LogFormat`` records the literal ``-`` rather
  than the authenticated user name, and ``mod_log_forensic`` and similar
  modules see no user either.
* Authorisation directives that need to evaluate against an identity, such
  as ``Require user`` and ``Require group``, have nothing to evaluate.

A small amount of glue can bridge this. The WSGI application emits the
authenticated user name and authentication scheme as response headers,
and a short ``mod_lua`` hook running in the logging phase copies the
values into ``r->user`` and ``r->ap_auth_type`` and strips the headers so
they are never sent to the HTTP client.

``mod_lua`` is part of the standard Apache distribution, although on some
platforms it is packaged as a separately installable module. Once it is
loaded, register a logging hook against a small Lua script::

    LoadModule lua_module modules/mod_lua.so

    LuaHookLog /etc/apache2/lua/wsgi-auth-reflect.lua reflect_auth

The script ``wsgi-auth-reflect.lua`` contains::

    function reflect_auth(r)
        local user = r.headers_out['X-Remote-User']
        if user then
            r.user = user
            r.headers_out['X-Remote-User'] = nil
        end

        local auth_type = r.headers_out['X-Auth-Type']
        if auth_type then
            r.ap_auth_type = auth_type
            r.headers_out['X-Auth-Type'] = nil
        end

        return apache2.OK
    end

The hook runs at the start of the logging phase, after the content
handler has produced the response but before ``mod_log_config`` writes
the access log entry, so ``%u`` records the user that the WSGI
application authenticated.

The WSGI application includes the two headers in the response when it
has authenticated the request::

    def application(environ, start_response):
        user = authenticate(environ)  # application specific

        headers = [('Content-Type', 'text/html; charset=utf-8')]
        if user is not None:
            headers.append(('X-Remote-User', user))
            headers.append(('X-Auth-Type', 'Bearer'))

        start_response('200 OK', headers)
        return [b'...']

The response headers are stripped only if the Lua hook is wired up
correctly. If the hook is not in place, the application leaks the
authenticated user name to the client, so the application should be
deployed together with the matching ``LuaHookLog`` configuration.

This bridge affects only what Apache logs and what downstream modules
observe at log time. It does not reactivate the Apache authorisation
phase, so it is not a substitute for ``Require user`` based access
control. Where Apache itself needs to make access decisions based on
the authenticated identity, the Apache authentication provider
mechanism described below should be used instead.

Apache Authentication Provider
------------------------------

Apache implements the concept of authentication providers. That is, Apache
implements the hand shaking with the client for authentication mechanisms
such as Basic and Digest. All that the user server side code needs to
provide is a means of authenticating the actual credentials of the user
trying to gain access to the site.

This greatly simplified the implementation of client authentication as the
hand shaking for a particular authentication mechanism was implemented only
once in Apache and it wasn't necessary for each authentication module to
duplicate it. This was particularly good for the Digest authentication
mechanism which was non trivial to implement correctly.

The WSGIAuthUserScript directive can be used to define a Python script file
containing code which performs the authenticating of user credentials as
outlined.

The required Apache configuration for defining the authentication provider
for Basic authentication would be::

    AuthType Basic
    AuthName "Top Secret"
    AuthBasicProvider wsgi
    WSGIAuthUserScript /usr/local/wsgi/scripts/auth.wsgi
    Require valid-user

The 'auth.wsgi' script would then need to contain a 'check_password()'
function with a sample as shown below::

    def check_password(environ, user, password):
        if user == 'spy':
            if password == 'secret':
                return True
            return False
        return None

This function should validate that the user exists in the user database and
that the password is correct. If the user does not exist at all, then the
result should be 'None'. If the user does exist, the result should be
'True' or 'False' depending on whether the password was valid.

As an alternative to returning ``True``, a non-empty string can be returned
to indicate that authentication has succeeded. The returned string is then
used as the authenticated user name in place of the value supplied by the
client — it becomes ``REMOTE_USER`` for the WSGI application, and is also
what Apache records for the request in access logs and in any subsequent
group authorisation checks. This is useful where the supplied user name
needs canonicalising, or where an external credential (an email address,
an LDAP attribute, a certificate subject) maps to a different internal
user name.

HTTP Digest authentication is uncommon in modern deployments — TLS plus
HTTP Basic authentication, or application-level authentication, is
generally preferred. Digest support is documented here for completeness.

If wishing to use Digest authentication, the configuration would instead
be::

    AuthType Digest
    AuthName "Top Secret"
    AuthDigestProvider wsgi
    WSGIAuthUserScript /usr/local/wsgi/scripts/auth.wsgi
    Require valid-user

The name of the required authentication function for Digest authentication
is 'get_realm_hash()'. The result of the function must be 'None' if the
user doesn't exist, or a hash string encoding the user name, authentication
realm and password::

    import hashlib

    def get_realm_hash(environ, user, realm):
        if user == 'spy':
            # user:realm:password
            data = ('%s:%s:%s' % (user, realm, 'secret')).encode('UTF-8')
            return hashlib.md5(data).hexdigest()
        return None

By default the auth providers are executed in the context of the main
Python interpreter, ie., '%{GLOBAL}' and always in the Apache child
processes, never in a daemon process. The interpreter can be overridden
using the 'application-group' option to the script directive. The namespace
for authentication groups is shared with that for application groups
defined by WSGIApplicationGroup.

Because the auth provider is always run in the Apache child processes and
never in the context of a mod_wsgi daemon process, if the authentication
check is making use of the internals of some Python web framework, it is
recommended that the application using that web framework also be run in
embedded mode and the same application group. This is the case as the
Python web frameworks often bring in a huge amount of code even if using
only one small part of them. This will result in a lot of memory being used
in the Apache child processes just to support the auth provider.

An aliased auth provider can also be defined using the
``<AuthnProviderAlias>`` directive (provided by ``mod_authn_core``, which
is loaded by default on Apache 2.4)::

    <AuthnProviderAlias wsgi django>
    WSGIAuthUserScript /usr/local/django/mysite/apache/auth.wsgi \
     application-group=django
    </AuthnProviderAlias>

    WSGIScriptAlias / /usr/local/django/mysite/apache/django.wsgi

    <Directory /usr/local/django/mysite/apache>
    Require all granted

    WSGIApplicationGroup django

    AuthType Basic
    AuthName "Django Site"
    AuthBasicProvider django
    Require valid-user
    </Directory>

An authentication script for Django might then be something like::

    import os, sys
    sys.path.append('/usr/local/django')
    os.environ['DJANGO_SETTINGS_MODULE'] = 'mysite.settings'

    from django.contrib.auth.models import User
    from django import db

    def check_password(environ, user, password):
        db.reset_queries() 

        kwargs = {'username': user, 'is_active': True} 

        try: 
            try: 
                user = User.objects.get(**kwargs) 
            except User.DoesNotExist: 
                return None

            if user.check_password(password): 
                return True
            else: 
                return False
        finally: 
            db.connection.close() 

For both Basic and Digest authentication providers, the 'environ' dictionary
passed as first argument is a cut down version of what would be supplied
to the actual WSGI application. This includes the 'wsgi.errors' object for
the purposes of logging error messages associated with the request.

Any configuration defined by SetEnv directives is not passed in the
'environ' dictionary because doing so would allow users to override the
configuration specified in such a way from a '.htaccess' file.
Configuration should as a result be placed into the script file itself.

The benefit of using the Apache authentication provider mechanism rather
than the WSGI application doing it all itself, is that it can be used to
control access to a number of WSGI applications at the same time as well as
static files or dynamic pages implemented by other Apache modules using
other programming languages such as PHP or Perl. The mechanism could even
be used to control access to CGI scripts.

Apache Group Authorisation
--------------------------

As complement to the authentication provider mechanism, mod_wsgi also
provides a mechanism for implementing group authorisation using the Apache
'Require' directive. To use this in conjunction with an inbuilt Apache
authentication provider such as a password file, the following Apache
configuration would be used::

    AuthType Basic
    AuthName "Top Secret"
    AuthBasicProvider dbm
    AuthDBMUserFile /usr/local/wsgi/accounts.dbm
    WSGIAuthGroupScript /usr/local/wsgi/scripts/auth.wsgi
    Require wsgi-group secret-agents
    Require valid-user

The 'auth.wsgi' script would then need to contain a 'groups_for_user()'
function with a sample as shown below::

    def groups_for_user(environ, user):
        if user == 'spy':
            return ['secret-agents']
        return []

The function should supply a list of groups the user is a member of or
an empty list otherwise.

The feature may be used with any authentication provider, including one
defined using WSGIAuthUserScript.

The 'environ' dictionary passed as first argument is a cut down version of
what would be supplied to the actual WSGI application. This includes the
'wsgi.errors' object for the purposes of logging error messages associated
with the request.

Any configuration defined by SetEnv directives is not passed in the
'environ' dictionary because doing so would allow users to override the
configuration specified in such a way from a '.htaccess' file.
Configuration should as a result be placed into the script file itself.

By default the group authorisation code is always executed in the context
of the main Python interpreter, ie., '%{GLOBAL}', and always in the Apache
child processes, never in a daemon process. The interpreter can be
overridden using the 'application-group' option to the script directive.

Host Access Controls
--------------------

The authentication provider and group authorisation features help to control
access based on the identity of a user. It is also possible to limit access
based on the machine which the client is connecting from. The path to the
script is defined using the WSGIAccessScript directive::

    WSGIAccessScript /usr/local/wsgi/script/access.wsgi

The name of the function that must exist in the script file is
'allow_access()'.  It must return True or False::

    def allow_access(environ, host):
        return host in ['localhost', '::1']

The 'environ' dictionary passed as first argument is a cut down version of
what would be supplied to the actual WSGI application. This includes the
'wsgi.errors' object for the purposes of logging error messages associated
with the request.

Any configuration defined by SetEnv directives is not passed in the
'environ' dictionary because doing so would allow users to override the
configuration specified in such a way from a '.htaccess' file.
Configuration should as a result be placed into the script file itself.

By default the access checking code is executed in the context of the main
Python interpreter, ie., '%{GLOBAL}', and always in the Apache child
processes, never in a daemon process. The interpreter used can be
overridden using the 'application-group' option to the script directive.

Using mod_wsgi-express
----------------------

When running under ``mod_wsgi-express``, the three script
directives covered above are configured through dedicated
command-line options. Each option emits the underlying
directive together with the surrounding ``AuthType`` /
``AuthBasicProvider`` / ``Require`` block needed to activate
it under a sitewide ``<Location />``, so the only argument you
need to supply is the script path itself.

``--host-access-script SCRIPT-PATH``
    Emits a ``WSGIAccessScript`` directive. The named script
    must define ``allow_access()`` as described in
    `Host Access Controls`_.

``--auth-user-script SCRIPT-PATH``
    Emits a ``WSGIAuthUserScript`` directive together with the
    ``AuthType``, ``AuthName``, ``Auth<scheme>Provider wsgi``
    and ``Require valid-user`` directives needed to make it
    active.

``--auth-type TYPE``
    Selects the authentication scheme: ``Basic`` (the default)
    or ``Digest``. The script function the named script must
    define is determined by this choice (``check_password()``
    for Basic, ``get_realm_hash()`` for Digest), as described
    in `Apache Authentication Provider`_.

``--auth-group-script SCRIPT-PATH``
    Emits a ``WSGIAuthGroupScript`` directive together with a
    ``Require wsgi-group`` directive. The named script must
    define ``groups_for_user()`` as described in
    `Apache Group Authorisation`_. Group authorisation is
    layered on top of user authentication, so this option is
    only meaningful in combination with ``--auth-user-script``.

``--auth-group NAME``
    Group name used in the generated ``Require wsgi-group``
    directive. Defaults to ``wsgi`` as a placeholder; override
    this to match the actual group name returned by your
    ``groups_for_user()`` function.

A typical invocation combining user authentication and group
authorisation::

    mod_wsgi-express start-server wsgi.py \
        --auth-user-script /srv/myapp/auth.wsgi \
        --auth-group-script /srv/myapp/auth.wsgi \
        --auth-group secret-agents

A single script file can supply both ``check_password()`` and
``groups_for_user()``, in which case ``--auth-user-script`` and
``--auth-group-script`` point at the same path. The scripts
run in the Apache child processes, with the same embedded-mode
caveats about framework loading costs described in the
sections above.
