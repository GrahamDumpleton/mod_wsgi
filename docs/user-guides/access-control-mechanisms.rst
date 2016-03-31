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
and setting it to 'On'. Note that prior to mod_wsgi version 2.0c5, this
directive could not be used in .htaccess files.

When passing of authorisation information is enabled, the authorisation
headers are passed through to a WSGI application in the
``HTTP_AUTHORIZATION`` variable of the WSGI application environment when
the equivalent HTTP request header is present. You will still need to
provide your own code to process the header and perform the required hand
shaking with the client to indicate whether the client is permitted access.

Apache Authentication Provider
------------------------------

When Apache 2.2 was released, it introduced the concept of authentication
providers. That is, Apache implements the hand shaking with the client for
authentication mechanisms such as Basic and Digest. All that the user
server side code needs to provide is a means of authenticating the actual
credentials of the user trying to gain access to the site.

This greatly simplified the implementation of client authentication as the
hand shaking for a particular authentication mechanism was implemented only
once in Apache and it wasn't necessary for each authentication module to
duplicate it. This was particularly good for the Digest authentication
mechanism which was non trivial to implement correctly.

Using mod_wsgi 2.0 or later, it is possible using the WSGIAuthUserScript
directive to define a Python script file containing code which performs the
authenticating of user credentials as outlined.

The required Apache configuration for defining the authentication provider
for Basic authentication when using Apache 2.2 would be::

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

If wishing to use Digest authentication, the configuration for Apache 2.2
would instead be::

    AuthType Digest
    AuthName "Top Secret"
    AuthDigestProvider wsgi
    WSGIAuthUserScript /usr/local/wsgi/scripts/auth.wsgi
    Require valid-user

The name of the required authentication function for Digest authentication
is 'get_realm_hash()'. The result of the function must be 'None' if the
user doesn't exist, or a hash string encoding the user name, authentication
realm and password::

    import md5

    def get_realm_hash(environ, user, realm):
        if user == 'spy':
            value = md5.new()
            # user:realm:password
            value.update('%s:%s:%s' % (user, realm, 'secret'))
            hash = value.hexdigest()
            return hash
        return None

By default the auth providers are executed in context of first interpreter
created by Python, ie., '%{GLOBAL}' and always in the Apache child
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

If mod_authn_alias is being loaded into Apache, then an aliased auth
%rovider can also be defined::

    <AuthnProviderAlias wsgi django>
    WSGIAuthUserScript /usr/local/django/mysite/apache/auth.wsgi \
     application-group=django
    </AuthnProviderAlias>

    WSGIScriptAlias / /usr/local/django/mysite/apache/django.wsgi

    <Directory /usr/local/django/mysite/apache>
    Order deny,allow
    Allow from all

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

Any configuration defined by !SetEnv directives is not passed in the
'environ' dictionary because doing so would allow users to override the
configuration specified in such a way from a '.htaccess' file.
Configuration should as a result be placed into the script file itself.

Although authentication providers were a new feature in Apache 2.2, the
mod_wsgi module emulates the functionality so that the above can also be
used with Apache 2.0. In using Apache 2.0, the required Apache configuration
is however slightly different and needs to be::

    AuthType Basic
    AuthName "Top Secret"
    WSGIAuthUserScript /usr/local/wsgi/scripts/auth.wsgi
    AuthAuthoritative Off
    Require valid-user

When using Apache 2.0 however, only support for Basic authentication
mechanism is provided. It is not possible to use Digest authentication.
When using Apache 1.3, this feature is not available at all.

The benefit of using the Apache authentication provider mechanism rather
than the WSGI application doing it all itself, is that it can be used to
control access to a number of WSGI applications at the same time as well as
static files or dynamic pages implemented by other Apache modules using
other programming languages such as PHP or Perl. The mechanism could even
be used to control access to CGI scripts.

Apache Group Authorisation
--------------------------

As compliment to the authentication provider mechanism, mod_wsgi 2.0 also
provides a mechanism for implementing group authorisation using the Apache
'Require' directive. To use this in conjunction with an inbuilt Apache
authentication provider such as a password file, the following Apache
configuration would be used::

    AuthType Basic
    AuthName "Top Secret"
    AuthBasicProvider dbm
    AuthDBMUserFile /usr/local/wsgi/accounts.dbm
    WSGIAuthGroupScript /usr/local/wsgi/scripts/auth.wsgi
    Require group secret-agents
    Require valid-user

The 'auth.wsgi' script would then need to contain a 'groups_for_user()'
function with a sample as shown below::

    def groups_for_user(environ, user):
        if user == 'spy':
            return ['secret-agents']
        return ['']

The function should supply a list of groups the user is a member of or
an empty list otherwise.

The feature may be used with any authentication provider, including one
defined using WSGIAuthUserScript.

The 'environ' dictionary passed as first argument is a cut down version of
what would be supplied to the actual WSGI application. This includes the
'wsgi.errors' object for the purposes of logging error messages associated
with the request.

Any configuration defined by !SetEnv directives is not passed in the
'environ' dictionary because doing so would allow users to override the
configuration specified in such a way from a '.htaccess' file.
Configuration should as a result be placed into the script file itself.

Configuration of group authorisation is the same whether Apache 2.0 or 2.2
is used. The feature is not available when using Apache 1.3.

By default the group authorisation code is always executed in the context
of the first interpreter created by Python, ie., '%{GLOBAL}', and always in
the Apache child processes, never in a daemon process. The interpreter can
be overridden using the 'application-group' option to the script directive.

Host Access Controls
--------------------

The authentication provider and group authorisation features help to control
access based on the identity of a user. Using mod_wsgi 2.0 it is also
possible to limit access based on the machine which the client is connecting
from. The path to the script is defined using the WSGIAccessScript
directive::

    WSGIAccessScript /usr/local/wsgi/script/access.wsgi

The name of the function that must exist in the script file is
'allow_access()'.  It must return True or False::

    def allow_access(environ, host):
        return host in ['localhost', '::1']

The 'environ' dictionary passed as first argument is a cut down version of
what would be supplied to the actual WSGI application. This includes the
'wsgi.errors' object for the purposes of logging error messages associated
with the request.

Any configuration defined by !SetEnv directives is not passed in the
'environ' dictionary because doing so would allow users to override the
configuration specified in such a way from a '.htaccess' file.
Configuration should as a result be placed into the script file itself.

By default the access checking code is executed in context of the first
interpreter created by Python, ie., '%{GLOBAL}', and always in the Apache
child processes, never in a daemon process. The interpreter used can be
overridden using the 'application-group' option to the script directive.
