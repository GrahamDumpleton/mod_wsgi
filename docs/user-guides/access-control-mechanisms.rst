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
