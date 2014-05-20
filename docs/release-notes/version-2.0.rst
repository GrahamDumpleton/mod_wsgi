===========
Version 2.0
===========

Version 2.0 of mod_wsgi can be obtained from:

  http://modwsgi.googlecode.com/files/mod_wsgi-2.0.tar.gz

Note that mod_wsgi 2.0 was originally derived from mod_wsgi 1.0. It has
though all changes from later releases in the 1.X branch. Thus also see:

* :doc:`version-1.1`
* :doc:`version-1.2`
* :doc:`version-1.3`

Bug Fixes
---------

1. Work around bug in Apache where '100 Continue' response was sent as
part of response content if no attempt to read request input before headers
and response were generated.

Features Changed
----------------

1. The WSGICaseSensitivity directive can now only be used at global scope
within the Apache configuration. This means that individual directories can
not be designated as being case sensitive or not. For correct operation
therefore, the path names of all script files should treat case the same,
one cannot have a mixture.

2. How the WSGIPythonPath directive is interpreted has changed in that
'.pth' files in the desiginated directories are honoured. See item 10 in
new features section for more information.

3. Removed support for output buffering outside of WSGI specification. In
other words, removed the WSGIOutputBuffering directive and associated code.
If using a WSGI application which does poor buffering itself, to the extent
that performance is affected, you will need to wrap it in a WSGI middleware
component that does buffering on its behalf.

Features Removed
----------------

1. The 'Interpreter' option to WSGIReloadMechanism has been removed. This
option for interpreter reloading was of limited practical value as many
third party modules for Python aren't written in a way to cope with
destruction of Python interpreters in a running process. The presence
of the feature was just making it harder to implement various new features.

2. The WSGIPythonHome directive is no longer available on Windows systems
as Python would ignore it anyway.

3. The WSGIPythonExecutable directive has been removed. This didn't work
on Windows or MacOS X systems. On UNIX systems, the WSGIPythonHome
directive should be used instead. Not known how one can achieve same on
Windows systems.

Features Added
--------------

1. The WSGIReloadMechanism now provides the 'Process' option for enabling
process reloading when the WSGI script file is changed. Note that this only
applies to WSGI script files used for WSGI applications which have been
delegated to a mod_wsgi daemon process. Additionally, as of 2.0c5 the use
of 'Process' option has been made the default for daemon mode processes.
If specifically requiring existing default behaviour, the 'Module' option
will need to be specified to indicate script file reloading.

If this option is specified for WSGI application run in embedded mode
within Apache child processes, the existing default behaviour of reloading
just the script file will apply.

For more details see:

  http://code.google.com/p/modwsgi/wiki/ReloadingSourceCode

2. When application is running in embedded mode, and WSGIApacheExtensions
directive is set to On, then a Python CObject reference is added to the
WSGI application environment as 'apache.request_rec'. This can be passed to
C extension modules and can be converted back to a reference to internal
Apache request_rec structure thereby allow C extension modules to work
against the internal Apache C APIs to implement special features.

One example of such special extensions are the Python SWIG bindings for the
Apache C API implemented in the separate 'ap_swig_py' package. Because SWIG
is being used, and due to thread support within SWIG generated bindings
possibly only being usable within the first Python interpreter instance
created, it may be the case that the 'ap_swig_py' package an only be used
when WSGIApplicationGroup has been set to '%{GLOBAL}'.

The 'ap_swig_py' package has not yet been released and is still in
development. The package can be obtained from the Subversion repository
at:

  https://bitbucket.org/grahamdumpleton/apswigpy/wiki/Home

With the SWIG binding for the Apache API, the intention is that many of
the internal features of Apache would then be available. For example::

  import apache.httpd, apache.http_core
  
  req = apache.httpd.request_rec(environ["apache.request_rec"])
  root = apache.http_core.ap_document_root(req)

Note that this feature is experimental and may be removed from a future
version if insufficient interest in it or in developing SWIG bindings.

3. When Apache 2.0/2.2 is being used, Python script can now be provided to
perform the role of an Apache auth provider. This would allow user
authentication underlying HTTP Basic (2.0 and 2.2) or Digest (2.2 only)
authentication schemes to be done by a Python web application. Do note
though that at present the provided authentication script will always
run in the context of the Apache child processes and can not be delegated
to a distinct daemon process.

Apache configuration for defining an auth provider for Basic authentication
when using Apache 2.2 would be::

  AuthType Basic
  AuthName "Top Secret"
  AuthBasicProvider wsgi
  WSGIAuthUserScript /usr/local/wsgi/scripts/auth.wsgi
  Require valid-user

For Apache 2.0 it would be::

  AuthType Basic
  AuthName "Top Secret"
  WSGIAuthUserScript /usr/local/wsgi/scripts/auth.wsgi
  AuthAuthoritative Off
  Require valid-user

The 'auth.wsgi' script would then need to contain a 'check_password()'
function with a sample as shown below::

  def check_password(environ, user, password):
      if user == 'spy':
          if password == 'secret':
              return True
          return False
      return None

If using Apache 2.2 and Digest authentication support is built into Apache,
then that also may be used::

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
created by Python. This can be overridden using the 'application-group'
option to the script directive. The namespace for authentication groups is
shared with that for application groups defined by WSGIApplicationGroup.

If mod_authn_alias is being loaded into Apache, then an aliased auth
provider can also be defined::

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

If the WSGIApacheExtensions directive is set to On then 'apache.request_rec'
will be passed in 'environ' to the auth provider functions. This may be used
in conjunction with C extension modules such as 'ap_swig_py'. For example,
it may be used to set attributes in 'req.subprocess_env' which are then in
turn passed to the WSGI application through the WSGI environment. Passing
of these settings will occur even if the WSGI application itself is running
in a daemon process.

A further example where this can be useful is where which daemon process
is used is dependent on some attribute of the user. For example, if using
the Apache configuration::

  WSGIDaemonProcess django-admin
  WSGIDaemonProcess django-users
  
  WSGIProcessGroup %{ENV:PROCESS_GROUP}

which daemon process the request is delegated to can be controlled from
the auth provider::

  import apache.httpd
  
  def check_password(environ, user, password): 
      db.reset_queries() 
  
      kwargs = {'username': user, 'is_active': True} 
  
      try: 
          try: 
              user = User.objects.get(**kwargs) 
          except User.DoesNotExist: 
              return None
  
          if user.check_password(password): 
              req = apache.httpd.request_rec(environ["apache.request_rec"])
  
              if user.is_staff:
                  req.subprocess_env["PROCESS_GROUP"] = 'django-admin'
              else:
                  req.subprocess_env["PROCESS_GROUP"] = 'django-users'
  
              return True
          else: 
              return False
      finally: 
          db.connection.close() 

For more details see:

  http://code.google.com/p/modwsgi/wiki/AccessControlMechanisms

4. When Apache 2.2 is being used, now possible to provide a script file
containing a callable which returns the groups that a user is a member of.
This can be used in conjunction with a 'group' option to the Apache
'Require' directive. Note that up to mod_wsgi 2.0c3 the option was actually
'wsgi-group'.

Apache configuration for defining an auth provider for Basic authentication
and subsequent group authorisation would be::

  AuthType Basic
  AuthName "Top Secret"
  AuthBasicProvider wsgi
  WSGIAuthUserScript /usr/local/wsgi/scripts/auth.wsgi
  WSGIAuthGroupScript /usr/local/wsgi/scripts/auth.wsgi
  Require group secret-agents
  Require valid-user

The 'auth.wsgi' script would then need to contain a 'check_password()'
and 'groups_for_user()' function with a sample as shown below::

  def check_password(environ, user, password):
      if user == 'spy':
          if password == 'secret':
              return True
          return False
      return None
  
  def groups_for_user(environ, user):
      if user == 'spy':
          return ['secret-agents']
      return ['']

For more details see:

  http://code.google.com/p/modwsgi/wiki/AccessControlMechanisms

5. Implemented WSGIDispatchScript directive. This directive can be used
to designate a script file in which can be optionally defined any of the
functions::

  def process_group(environ):
      return "%{GLOBAL}"
  
  def application_group(environ):
      return "%{GLOBAL}"
  
  def callable_object(environ):
      return "application"

This allows for the process group, application group and callable object
name for a WSGI application to be programmatically defined rather than be
exclusively drawn from the configuration.

Each function if wishing to override the value defined by the configuration
should return a string object. If None is returned then value defined by
the configuration will still be used.

By default the script file code will be executed within the context of the
'%{GLOBAL}' application group within the Apache child processes (never in
the daemon processes). The application group used can be overridden by
defining the 'application-group' option to the script directive. Note that
up to 2.0c3 the WSGIServerGroup directive was instead provided, but this
has now been removed.

This feature could be used as part of a mechanism for distributing requests
across a number of daemon process groups, but always directing requests from
a specific user to the same daemon process.

6. Implemented inactivity-timeout option for WSGIDaemonProcess directive.
For example::

  WSGIDaemonProcess trac processes=1 threads=15 \
    maximum-requests=1000 inactivity-timeout=300

When this option is used, the daemon process will be shutdown, and thence
restarted, after no request activity for the defined period (in seconds).

The purpose of this option is to allow amount of memory being used by a
process to be dropped back to the initial idle state level. This option
would be used where the application delegated to the daemon process was
used infrequently and thus it would be preferable to reclaim the memory
when the application is not in use.

7. In daemon processes, the HOME environment variable is now overridden
such that its initial value when a new Python sub interpreter is created
is the same as the home directory of the user that the daemon process is
running as. This is to give some certainty as to its value as otherwise
the HOME environment variable may be that of the root user, a particular
user, or the user that ran 'sudo' to start Apache. This is because HOME
environment variable will be inherited from environment of user that Apache
is started as and has no relationship to the user that the process is
actually run as.

Note that the HOME environment variable is not updated for embedded mode as
this would change the environment of code running under different Apache
modules, such as mod_php and mod_perl. Not seen as being good practice to
modify the environment of other systems.

Once consequence of the HOME environment variable being set correctly for
daemon processes at least, is that the default location calculated for
Python egg cache should then be correct. If running in embedded mode, would
still be necessary to manually override Python egg cache location.

8. In daemon processes, the initial current working directory of the
process will be set to the home directory of the user that the process
runs as, or as specified by the 'home' option to the WSGIDaemonProcess
directive.

9. Added 'stack-size' option to WSGIDaemonProcess so that per thread stack
size can be overridden for processes in the daemon process group.

This can be required on Linux where the default stack size for threads is
the same as the default user process stack size, that being 8MB. When
running in a VPS provided by a web hosting company, where they for some
reason seem to take into consideration the virtual memory size as well as
the resident memory size when calculating your process limits, it is better
to drop the per thread stack size down to a value closer to 512KB. For
example::

  WSGIDaemonProcess example processes=2 threads=25 stack-size=524288

10. Added some direct support into mod_wsgi for virtual environments for
Python such as virtualenv and workingenv.

The first approach to configuration is to use WSGIPythonPath directive at
global scope in apache configuration. For example::

  # workingenv
  WSGIPythonPath /some/path/env/lib/python2.3
  
  # virtualenv
  WSGIPythonPath /some/path/env/lib/python2.3/site-packages

The path you have to specify is slightly different depending on whether you
use workingenv or virtualenv packages.

Previously the WSGIPythonPath directive would just override the
``PYTHONPATH`` environment variable. Instead it now calls
``site.addsitedir()`` for any specified directories, thus triggering the
reading of any .pth files and the subsequent addition of further
directories there specified to sys.path.

Note that directories added with WSGIPythonPath only apply to applications
running in embedded mode.

If you want to specify directories for daemon processes, you can use the
'python-path' option to WSGIDaemonProcess. For example::

  WSGIDaemonProcess turbogears processes=5 threads=1 \
    user=site1 group=site1 maximum-requests=1000 \
    python-path=/some/path/env/lib/python2.3/site-packages
  
  WSGIScriptAlias / /some/path/scripts/turbogears.wsgi
  
  WSGIProcessGroup turbogears
  WSGIApplicationGroup %{GLOBAL}
  WSGIReloadMechanism Process

Do note that anything defined in the standard Python site-packages
directories takes precedence over directories added using the mechanisms
described above. Thus, if wanting to use these virtual environments all the
time, your standard Python installation effectively needs to have an empty
site-packages directory. Alternatively, on UNIX systems you can use the
WSGIPythonHome directive to point to a virtual environment which contains
an empty 'site-packages'.

End result is that with these options, should be very easy to have
different daemon process groups using different Python virtual
environments without any fiddles having to be done in the WSGI script
file itself. 

For more details see:

  http://code.google.com/p/modwsgi/wiki/VirtualEnvironments

11. Added WSGIPythonEggs directive and corresponding 'python-eggs' option
for WSGIDaemonProcess directive. These allow the location of the Python
egg cache directive to be set for applications running in embedded mode or
in the designated daemon processes. These options have the same affect as
if the 'PYTHON_EGG_CACHE' environment variable had been set.

12. Implement 'deadlock-timeout' option for WSGIDaemonProcess for detecting
Python programs that hold the GIL for extended periods, thus perhaps
indicating that process has frozen or has become unresponsive. The default
value for the timeout is 300 seconds.

13. Added support for providing an access control script. This equates to
the access handler phase of Apache and would be use to deny access to a
subset of URLs based on the details of the remote client. The path to the
script is defined using the WSGIAccessScript directive::

  WSGIAccessScript /usr/local/wsgi/script/access.wsgi

The name of the function that must exist in the script file is 'allow_access()'.
It must return True or False::

  def allow_access(environ, host):
      return host in ['localhost', '::1']

This function will always be executed in the context of the Apache child
processes even if it is controlling access to a WSGI application which has
been delegated to a daemon process. By default the function will be executed
in the context of the main Python interpreter, ie., '%{GLOBAL}'. This can
be overridden by using the 'application-group' option to the WSGIAccessScript
directive::

  WSGIAccessScript /usr/local/wsgi/script/access.wsgi application-group=admin

For more details see documentation on
[AccessControlMechanisms Access Control Mechanisms]

14. Added support for loading a script file at the time that process is
first started. This would allow modules related to an application to be
preloaded into an interpreter immediately rather than it only occuring when
the first request arrives for that application.

The directive for designating the script to load is WSGIImportScript. The
directive can only be used at global scope within the Apache configuration.
It is necessary to designate both the application group, and if dameon mode
support is available, the process group::

  WSGIImportScript /usr/local/wsgi/script/import.wsgi \
   process-group=%{GLOBAL} application-group=django

14. Add "--disable-embedded" option to "configure" script so that ability
to run a WSGI application in embedded mode can be disabled completely.
Also added the directive WSGIRestrictEmbedded so that ability to run a
WSGI application in embedded mode can be disabled easily if support for
embedde mode is still compiled in.

15. Added support for optional WSGI extension wsgi.file_wrapper. On UNIX
systems and when Apache 2.X is being used, if the wrapped file like object
relates to a regular file then additional optimisations will be applied to
improve the performance of returning the file in a response.

16. Added 'display-name' option for WSGIDaemonProcess. On operating systems
where it works, this should allow displayed name of daemon process shown by
'ps' to be changed. Note that name will be truncated to whatever the existing
length of 'argv[0]' was for the process.

17. When WSGI application generates more content than what was defined by
response content length header, excess is discarded. If Apache log level is
set to debug, messages will be logged to Apache error log file warning of
when generated content length differs to specified content length.

18. Allow WSGIPassAuthorization to be used in .htaccess file if !FileInfo
override has been set. This has been allowed as !FileInfo enables ability to
use both mod_rewrite and mod_headers, which both provide means of getting
at the authorisation header anyway, so no point trying to block it.

19. Optimise sending of WSGI environment across to daemon process by
reducing number of writes to socket. For daemon mode and a simple hello
world application this improves base performance by 40% moving it
significantly closer to performance of embedded mode.

20. Always change a HEAD request into a GET request. This is to ensure that
a WSGI application always generates response content. If this isn't done
then any Apache output filters will not get to see the response content and
if they need to see the response content to generate headers based on it,
then the response headers from a HEAD request would be incorrect and not
match a GET request as required.

If Apache 2.X, this will not however be done if there are no Apache output
filters registered which could change the response headers or content.

21. Add option "send-buffer-size" and "receive-buffer-size" to
WSGIDaemonProcess for controlling the send and receive buffer sizes of the
UNIX socket used to communicate with mod_wsgi daemon processes. This is to
work around or limit deadlock problems that can occur in certain cases
when the operating system defines a very small default UNIX socket buffer
size.

22. When no request content has been read and headers are to be sent back,
force a zero length read in order to flush out any '100 Continue' response
if expected by client. This is only done for 2xx and 3xx response status
values.

23. A negative value for content length in response wasn't being rejected.
Where invalid header was being returned in response original response
status was being returned instead of a 500 error.
