========================
Configuration Guidelines
========================

The purpose of this document is to detail the basic configuration steps
required for running WSGI applications with mod_wsgi.

The WSGIScriptAlias Directive
-----------------------------

Configuring Apache to run WSGI applications using mod_wsgi is similar to
how Apache is configured to run CGI applications. To streamline this task
however, an additional configuration directive called WSGIScriptAlias is
provided. Like the ScriptAlias directive for CGI scripts, the mod_wsgi
directive combines together a number of steps so as to reduce the amount of
configuration required.

The first way of using the WSGIScriptAlias directive to indicate the WSGI
application to be used, is to associate a WSGI application against a
specific URL prefix::

    WSGIScriptAlias /myapp /usr/local/wsgi/scripts/myapp.wsgi

The last option to the directive in this case must be a full pathname to
the actual code file containing the WSGI application. A trailing slash
should never be added to the last option when it is referring to an actual
file.

The WSGI application contained within the code file specified should be
called 'application'. For example::

    def application(environ, start_response):
        status = '200 OK' 
        output = b'Hello World!'

        response_headers = [('Content-type', 'text/plain'),
                            ('Content-Length', str(len(output)))]
        start_response(status, response_headers)

        return [output]

Note that an absolute pathname to a WSGI script file must be provided. It
is not possible to specify an application by Python module name alone. A
full path is used for a number of reasons, the main one being so that all
the Apache access controls can still be applied to indicate who can
actually access the WSGI application. Because these access controls will
apply, if the WSGI application is located outside of any directories
already known to Apache, it will be necessary to tell Apache that files
within that directory can be used. To do this the Directory directive must
be used::

    <Directory /usr/local/wsgi/scripts>
    Order allow,deny
    Allow from all
    </Directory>

Note that Apache access control directives such as Order and Allow should
nearly always be applied to Directory and never to a Location. Adding them
to a Location would not be regarded as best practice and would potentially
weaken the security of your Apache server, especially where the Location
was for '/'.

As for CGI scripts and the ScriptAlias directive, it is not necessary to
have used the Options directive to enable the ExecCGI directive. This is
because it is automatically implied from the use of the WSGIScriptAlias
directive that the script must be executable.

For WSGIScriptAlias, to mount a WSGI application at the root of the web
site, simply use '/' as the mount point::

    WSGIScriptAlias / /usr/local/wsgi/scripts/myapp.wsgi

If you need to mount multiple WSGI applications, the directives can be
listed more than once. When this occurs, those occuring first are given
precedence. As such, those which are mounted at what would be a sub URL to
another WSGI application, should always be listed earlier::

    WSGIScriptAlias /wiki /usr/local/wsgi/scripts/mywiki.wsgi
    WSGIScriptAlias /blog /usr/local/wsgi/scripts/myblog.wsgi
    WSGIScriptAlias / /usr/local/wsgi/scripts/myapp.wsgi

The second way of using the WSGIScriptAlias directive is to use it to map
to a directory containing any number of WSGI applications::

    WSGIScriptAlias /wsgi/ /usr/local/wsgi/scripts/

When this is used, the next part of the URL after the URL prefix is used to
identify which WSGI application script file within the target directory
should be used. Both the mount point and the directory path must have a
trailing slash.

If you want WSGI application scripts to use an extension, but don't wish
to have that extension appear in the URL, then it is possible to use the
WSGIScriptAliasMatch directive instead::

    WSGIScriptAliasMatch ^/wsgi/([^/]+) /usr/local/wsgi/scripts/$1.wsgi

In this case, any path information appearing after the URL prefix, will be
mapped to a corresponding WSGI script file in the directory, but with a
'.wsgi' extension. The extension would though not need to be included in
the URL.

In all ways that the WSGIScriptAlias can be used, the target script is not
required to have any specific extension type and in particular it is not
necessary to use a '.py' extension just because it contains Python code.
Because the target script is not treated exactly like a traditional Python
module, if an extension is used, it is recommended that '.wsgi' be used
rather than '.py'.

The Apache Alias Directive
--------------------------

Although the WSGIScriptAlias directive is provided, the traditional Alias
directive can still be used to enable execution of WSGI applications for
specific URLs. The equivalent such configuration for::

    WSGIScriptAlias /wsgi/ /usr/local/wsgi/scripts/

    <Directory /usr/local/wsgi/scripts>
    Order allow,deny
    Allow from all
    </Directory>

using the Alias directive would be::

    Alias /wsgi/ /usr/local/wsgi/scripts/

    <Directory /usr/local/wsgi/scripts>
    Options ExecCGI

    SetHandler wsgi-script

    Order allow,deny
    Allow from all
    </Directory>

The additional steps required in this case are to enable the ability to
execute CGI like scripts using the Options directive and define the Apache
handler as 'wsgi-script'.

If wishing to hold a mixture of static files, normal CGI scripts and WSGI
applications within the one directory, the AddHandler directive can be
used instead of the SetHandler directive to distinguish between the various
resource types based on resource extension::

    Alias /wsgi/ /usr/local/wsgi/scripts/

    <Directory /usr/local/wsgi/scripts>
    Options ExecCGI

    AddHandler cgi-script .cgi
    AddHandler wsgi-script .wsgi

    Order allow,deny
    Allow from all
    </Directory>

For whatever extension you use to identify a WSGI script file, ensure that
you do not have a conflicting definition for that extension marking it as a
CGI script file. For example, if you previously had all '.py' files being
handled as 'cgi-script', consider disabling that before marking '.py' file
as then being handled as 'wsgi-script' file in same context. If both are
defined in same context, which is used will depend on the order of the
directives and the wrong handler may be selected.

Because an extension is required to determine whether a script should be
processed as a CGI script versus a WSGI application, the extension would
need to appear in the URL. If this is not desired, then add the MultiViews
option and MultiviewsMatch directive::

    Alias /wsgi/ /usr/local/wsgi/scripts/

    <Directory /usr/local/wsgi/scripts>
    Options ExecCGI MultiViews
    MultiviewsMatch Handlers

    AddHandler cgi-script .cgi
    AddHandler wsgi-script .wsgi

    Order allow,deny
    Allow from all
    </Directory>

Adding of MultiViews in this instance and allowing multiviews to match
Apache handlers will allow the extension to be dropped from the URL.
Provided that for each resource there is only one alternative, Apache will
then automatically select either the CGI script or WSGI application as
appropriate for that resource. Use of multiviews in this way would make it
possible to transparently migrate from CGI scripts to WSGI applications
without the need to change any URLs.

A benefit of using the AddHandler directive as described above, is that it
also allows a directory index page or directory browsing to be enabled for
the directory. To enable directory browsing add the Indexes option::

    Alias /wsgi/ /usr/local/wsgi/scripts/

    <Directory /usr/local/wsgi/scripts>
    Options ExecCGI Indexes

    AddHandler cgi-script .cgi
    AddHandler wsgi-script .wsgi

    Order allow,deny
    Allow from all
    </Directory>

If a directory index page is enabled, it may refer to either a static file,
CGI or WSGI application. The DirectoryIndex directive should be used to
designate what should be used for the index page::

    Alias /wsgi/ /usr/local/wsgi/scripts/

    <Directory /usr/local/wsgi/scripts>
    Options ExecCGI Indexes

    DirectoryIndex index.html index.wsgi index.cgi

    AddHandler cgi-script .cgi
    AddHandler wsgi-script .wsgi

    Order allow,deny
    Allow from all
    </Directory>

Using AddHandler or SetHandler to configure a WSGI application can also
be done from within the '.htaccess' file located within the directory which
a URL maps to. This will however only be possible where the directory has
been enabled to allow these directives to be used. This would be done using
the AllowOverride directive and enabling FileInfo for that directory.
It would also be necessary to allow the execution of scripts using the
Options directive by listing ExecCGI::

    Alias /site/ /usr/local/wsgi/site/

    <Directory /usr/local/wsgi/site>
    AllowOverride FileInfo
    Options ExecCGI MultiViews Indexes
    MultiviewsMatch Handlers

    Order allow,deny
    Allow from all
    </Directory>

This done, the '.htaccess' file could then contain::

    DirectoryIndex index.html index.wsgi index.cgi

    AddHandler cgi-script .cgi
    AddHandler wsgi-script .wsgi

Note that the DirectoryIndex directive can only be used to designate a
simple WSGI application which returns a single page for when the URL maps
to the actual directory. Because the DirectoryIndex directive is not
applied when the URL has additional path information beyond the leading
portion of the URL which mapped to the directory, it cannot be used as a
means of making a complex WSGI application responding to numerous URLs
appear at the root of a server.

When using the AddHandler directive, with WSGI applications identified by
the extension of the script file, the only way to make the WSGI application
appear as the root of the server is to perform on the fly rewriting of the
URL internal to Apache using mod_rewrite. The required rules for
mod_rewrite to ensure that a WSGI application, implemented by the script
file 'site.wsgi' in the root directory of the virtual host, appears as being
mounted on the root of the virtual host would be::

    RewriteEngine On
    RewriteCond %{REQUEST_FILENAME} !-f
    RewriteRule ^(.*)$ /site.wsgi/$1 [QSA,PT,L]

Do note however that when the WSGI application is executed for a request
the 'SCRIPT_NAME' variable indicating what the mount point of the application
was will be '/site.wsgi'. This will mean that when a WSGI application
constructs an absolute URL based on 'SCRIPT_NAME', it will include
'site.wsgi' in the URL rather than it being hidden. As this would probably
be undesirable, many web frameworks provide an option to override what the
value for the mount point is. If such a configuration option isn't
available, it is just as easy to adjust the value of 'SCRIPT_NAME' in the
'site.wsgi' script file itself::

    def _application(environ, start_response):
        # The original application.
        ...

    import posixpath

    def application(environ, start_response):
        # Wrapper to set SCRIPT_NAME to actual mount point.
        environ['SCRIPT_NAME'] = posixpath.dirname(environ['SCRIPT_NAME'])
        if environ['SCRIPT_NAME'] == '/':
            environ['SCRIPT_NAME'] = ''
        return _application(environ, start_response)

This wrapper will ensure that 'site.wsgi' never appears in the URL as long
as it wasn't included in the first place and that access was always via the
root of the web site instead.

Application Configuration
-------------------------

If it is necessary or desired to be able to pass configuration information
through to a WSGI application from the Apache configuration file, then the
SetEnv directive can be used::

    WSGIScriptAlias / /usr/local/wsgi/scripts/demo.wsgi

    SetEnv demo.templates /usr/local/wsgi/templates
    SetEnv demo.mailhost mailhost
    SetEnv demo.debugging 0

Any such variables added using the SetEnv directive will be automatically
added to the WSGI environment passed to the application when executed.

Note that the WSGI environment is passed upon each request to the
application in the 'environ' argument of the application object. This
environment is totally unrelated to the process environment which is
kept in 'os.environ'. The SetEnv directive has no effect on 'os.environ'
and there is no way through Apache configuration directives to affect
what is in the process environment.

If needing to dynamically set variables based on some aspects of the
request itself, the RewriteRule directive may also be useful in some cases
as an avenue to set application configuration variables.

For example, to enable additional debug only when the client is connecting
from the localhost, the following might be used::

    SetEnv demo.debugging 0

    RewriteEngine On
    RewriteCond %{REMOTE_ADDR} ^127.0.0.1$
    RewriteRule . - [E=demo.debugging:1]

More elaborate schemes involving RewriteMap could also be employed.

Where SetEnv and RewriteRule are insufficient, then any further
application configuration should be injected into an application using a
WSGI application wrapper within the WSGI application script file::

    def _application(environ, start_response):
        ...

    def application(environ, start_response):
        if environ['REMOTE_ADDR'] in ['127.0.0.1']:
            environ['demo.debugging'] = '1'
        return _application(environ, start_response)

User Authentication
-------------------

As is the case when using CGI scripts with Apache, authorisation headers
are not passed through to WSGI applications. This is the case, as doing so
could leak information about passwords through to a WSGI application which
should not be able to see them when Apache is performing authorisation.

Unlike CGI scripts however, when using mod_wsgi, the WSGIPassAuthorization
directive can be used to control whether HTTP authorisation headers are
passed through to a WSGI application in the ``HTTP_AUTHORIZATION``
variable of the WSGI application environment when the equivalent HTTP
request headers are present. This option would need to be set to ``On``
if the WSGI application was to handle authorisation rather than Apache
doing it::

    WSGIPassAuthorization On

If Apache is performing authorisation and not the WSGI application, a WSGI
application can still find out what type of authorisation scheme was used
by checking the variable ``AUTH_TYPE`` of the WSGI application
environment. The login name of the authorised user can be determined by
checking the variable ``REMOTE_USER``.

Hosting Of Static Files
-----------------------

When the WSGIScriptAlias directive is used to mount an application at the
root of the web server for a host, all requests for that host will be
processed by the WSGI application. If is desired for performance reasons
to still use Apache to host static files associated with the application,
then the Alias directive can be used to designate the files and directories
which should be served in this way::

    Alias /robots.txt /usr/local/wsgi/static/robots.txt
    Alias /favicon.ico /usr/local/wsgi/static/favicon.ico

    AliasMatch /([^/]*\.css) /usr/local/wsgi/static/styles/$1

    Alias /media/ /usr/local/wsgi/static/media/

    <Directory /usr/local/wsgi/static>
    Order deny,allow
    Allow from all
    </Directory>

    WSGIScriptAlias / /usr/local/wsgi/scripts/myapp.wsgi

    <Directory /usr/local/wsgi/scripts>
    Order allow,deny
    Allow from all
    </Directory>

When listing the directives, list those for more specific URLs first. In
practice this shouldn't actually be required as the Alias directive should
take precedence over WSGIScriptAlias, but good practice all the same.

Do note though that if using Apache 1.3, the Alias directive will only take
precedence over WSGIScriptAlias if the mod_wsgi module is loaded prior to
the mod_alias module. To ensure this, the LoadModule/AddModule directives
are used.

Note that there is never a need to use SetHandler to reset the Apache
content handler back to 'None' for URLs mapped to static files. That this
is a requirement for mod_python is a short coming in mod_python, do not do
the same thing for mod_wsgi.

Limiting Request Content
------------------------

By default Apache does not limit the amount of data that may be pushed to
the server via a HTTP request such as a POST. That this is the case means
that malicious users could attempt to overload a server by attempting to
upload excessively large amounts of data.

If a WSGI application is not designed properly and doesn't limit this
itself in some way, and attempts to load the whole request content into
memory, it could cause an application to exhaust available memory.

If it is unknown if a WSGI application properly protects itself against
such attempts to upload excessively large amounts of data, then the Apache
LimitRequestBody directive can be used::

    LimitRequestBody 1048576

The argument to the LimitRequestBody should be the maxumum number of bytes
that should be allowed in the content of a request.

When this directive is used, mod_wsgi will perform the check prior to
actually passing a request off to a WSGI application. When the limit is
exceeded mod_wsgi will immediately return the HTTP 413 error response
without even invoking the WSGI application to handle the request. Any
request content will not be read as the client connection will then be
closed.

Note that the HTTP 413 error response page will be that defined by Apache,
or as specified by the Apache ErrorDocument directive for that error type.

Defining Application Groups
---------------------------

By default each WSGI application is placed into its own distinct
application group. This means that each application will be given its own
distinct Python sub interpreter to run code within. Although this means
that applications will be isolated and cannot in general interfere with the
Python code components of each other, each will load its own copy of all
Python modules it requires into memory. If you have many applications and
they use a lot of different Python modules this can result in large process
sizes.

To avoid large process sizes, if you know that applications within a 
directory can safely coexist and run together within the same Python sub
interpreter, you can specify that all applications within a certain context
should be placed in the same application group. This is indicated by using
the WSGIApplicationGroup directive::

    <Directory /usr/local/wsgi/scripts>
    WSGIApplicationGroup admin-scripts

    Order allow,deny
    Allow from all
    </Directory>

The argument to the WSGIApplicationGroup directive can in general be any
unique name of your choosing, although there are also a number of special
values which you can use as well. For further information about these
special values see the more detailed documentation on the
:doc:`../configuration-directives/WSGIApplicationGroup` directive. Two of the
special values worth highlighting are:

**%{GLOBAL}**

    The application group name will be set to the empty string.

    Any WSGI applications in the global application group will always be
    executed within the context of the first interpreter created by Python
    when it is initialised. Forcing a WSGI application to run within the
    first interpreter can be necessary when a third party C extension
    module for Python has used the simplified threading API for
    manipulation of the Python GIL and thus will not run correctly within
    any additional sub interpreters created by Python.

**%{ENV:variable}**

    The application group name will be set to the value of the named
    environment variable. The environment variable is looked-up via the
    internal Apache notes and subprocess environment data structures and
    (if not found there) via getenv() from the Apache server process.

In an Apache configuration file, environment variables accessible
using the ``%{ENV}`` variable reference can be setup by using directives
such as SetEnv and RewriteRule.

For example, to group all WSGI scripts for a specific user when using
mod_userdir within the same application group, the following could be used::

    RewriteEngine On
    RewriteCond %{REQUEST_URI} ^/~([^/]+)
    RewriteRule . - [E=APPLICATION_GROUP:~%1]

    <Directory /home/*/public_html/wsgi-scripts/>
    Options ExecCGI
    SetHandler wsgi-script
    WSGIApplicationGroup %{ENV:APPLICATION_GROUP}
    </Directory>

Defining Process Groups
-----------------------

By default all WSGI applications will run in what is called 'embedded'
mode. That is, the applications are run within Python sub interpreters
hosted within the Apache child processes. Although this results in the best
performance possible, there are a few down sides.

First off, embedded mode is not recommended where you are not adept at
tuning Apache. This is because the default MPM settings are never usually
suitable for Python web applications, instead being biased towards static
file serving and PHP applications. If you run embedded mode without tuning
the MPM settings, you can experience problems with memory usage, due to
default number of processes being too many, and can also experience load
spikes, due to how Apache performs lazy creation of processes to meet
demand.

Secondly, embedded mode would not be suitable for shared web hosting
environments as all applications run as the same user and through various
means could interfere with each other.

Running multiple Python applications within the same process, even if
separated into distinct sub interpreters also presents other challenges and
problems. These include problems with Python extension modules not being
implemented correctly such that they work from a secondary sub interpreter,
or when used from multiple sub interpreters at the same time.

Where multiple applications, potentially owned by different users, need to
be run, 'daemon' mode of mod_wsgi should instead be used. Using daemon
mode, each application can be delegated to its own dedicated daemon process
running just the WSGI application, with the Apache child processes merely
acting as proxies for delivering the requests to the application. Any
static files associated with the application would still be served up by
the Apache child processes to ensure best performance possible.

To denote that a daemon process should be created the WSGIDaemonProcess
directive is used. The WSGIProcessGroup directive is then used to delegate
specific WSGI applications to execute within that daemon process::

    WSGIDaemonProcess www.site.com threads=15 maximum-requests=10000

    Alias /favicon.ico /usr/local/wsgi/static/favicon.ico

    AliasMatch /([^/]*\.css) /usr/local/wsgi/static/styles/$1

    Alias /media/ /usr/local/wsgi/static/media/

    <Directory /usr/local/wsgi/static>
    Order deny,allow
    Allow from all
    </Directory>

    WSGIScriptAlias / /usr/local/wsgi/scripts/myapp.wsgi
    WSGIProcessGroup www.site.com

    <Directory /usr/local/wsgi/scripts>

    Order allow,deny
    Allow from all
    </Directory>

Where Apache has been started as the ``root`` user, the daemon processes
can optionally be run as a user different to that which the Apache child
processes would normally be run as. The number of daemon processes making
up the process group and whether they are single or multithreaded can also
be controlled.

A further option which should be considered is that which dictates the
maximum number of requests that a daemon process should be allowed to
accept before the daemon process is shutdown and restarted. This should be
used where there are problems with increasing memory use due to problems
with the application itself or a third party extension module.

As a general recommendation it would probably be a good idea to use the
maximum requests option when running large installations of packages such
as Trac and MoinMoin. Any large web site based on frameworks such as
Django, TurboGears and Pylons or applications which use a database backend
may also benefit.

If an application does not shutdown cleanly when the maximum number of
requests has been reached, it will be killed off after the shutdown timeout
has expired. If this occurs on a regular basis you should run with more
than a single daemon process in the process group such that the other
process can still accept requests while the first is being restarted.

If the maximum requests option is not specified, then the daemon process
will never expire and will only be restarted if Apache is restarted or the
user explicitly signals it to restart.

For further information about the options that can be supplied to the
WSGIDaemonProcess directive see the more detailed documentation for
:doc:`../configuration-directives/WSGIDaemonProcess`. A few of the options
which can be supplied to the WSGIDaemonProcess directive worth highlighting
are:

**user=name | user=#uid**

    Defines the UNIX user _name_ or numeric user _uid_ of the user that
    the daemon processes should be run as. If this option is not supplied
    the daemon processes will be run as the same user that Apache would
    run child processes and as defined by the User directive.

    Note that this option is ignored if Apache wasn't started as the root
    user, in which case no matter what the settings, the daemon processes
    will be run as the user that Apache was started as.

**group=name | group=#gid**

    Defines the UNIX group _name_ or numeric group _gid_ of the primary
    group that the daemon processes should be run as. If this option is not
    supplied the daemon processes will be run as the same group that Apache
    would run child processes and as defined by the Group directive.

    Note that this option is ignored if Apache wasn't started as the root
    user, in which case no matter what the settings, the daemon processes
    will be run as the group that Apache was started as.

**processes=num**

    Defines the number of daemon processes that should be started in this
    process group. If not defined then only one process will be run in this
    process group.

    Note that if this option is defined as 'processes=1', then the WSGI
    environment attribute called 'wsgi.multiprocess' will be set to be True
    whereas not providing the option at all will result in the attribute
    being set to be False. This distinction is to allow for where some form
    of mapping mechanism might be used to distribute requests across
    multiple process groups and thus in effect it is still a multiprocess
    application. If you need to ensure that 'wsgi.multiprocess' is False so
    that interactive debuggers will work, simply do not specify the
    'processes' option and allow the default single daemon process to be
    created in the process group.

**threads=num**

    Defines the number of threads to be created to handle requests in each
    daemon process within the process group.

    If this option is not defined then the default will be to create 15
    threads in each daemon process within the process group.

**maximum-requests=nnn**

    Defines a limit on the number of requests a daemon process should
    process before it is shutdown and restarted. Setting this to a non zero
    value has the benefit of limiting the amount of memory that a process
    can consume by (accidental) memory leakage.

    If this option is not defined, or is defined to be 0, then the daemon
    process will be persistent and will continue to service requests until
    Apache itself is restarted or shutdown.

Note that the name of the daemon process group must be unique for the whole
server. That is, it is not possible to use the same daemon process group
name in different virtual hosts.

If the WSGIDaemonProcess directive is specified outside of all virtual
host containers, any WSGI application can be delegated to be run within
that daemon process group. If the WSGIDaemonProcess directive is specified
within a virtual host container, only WSGI applications associated with
virtual hosts with the same server name as that virtual host can be
delegated to that set of daemon processes.

When WSGIDaemonProcess is associated with a virtual host, the error log
associated with that virtual host will be used for all Apache error log
output from mod_wsgi rather than it appear in the main Apache error log.

For example, if a server is hosting two virtual hosts and it is desired
that the WSGI applications related to each virtual host run in distinct
processes of their own and as a user which is the owner of that virtual
host, the following could be used::

    <VirtualHost *:80>
    ServerName www.site1.com
    CustomLog logs/www.site1.com-access_log common
    ErrorLog logs/ww.site1.com-error_log

    WSGIDaemonProcess www.site1.com user=joe group=joe processes=2 threads=25
    WSGIProcessGroup www.site1.com

    ...
    </VirtualHost>

    <VirtualHost *:80>
    ServerName www.site2.com
    CustomLog logs/www.site2.com-access_log common
    ErrorLog logs/www.site2.com-error_log

    WSGIDaemonProcess www.site2.com user=bob group=bob processes=2 threads=25
    WSGIProcessGroup www.site2.com

    ...
    </VirtualHost>

When using the WSGIProcessGroup directive, the argument to the directive
can be either one of two special expanding variables or the actual name of
a group of daemon processes setup using the WSGIDaemonProcess directive.
The meaning of the special variables are:

**%{GLOBAL}**

    The process group name will be set to the empty string.
    Any WSGI applications in the global process group will always be
    executed within the context of the standard Apache child processes.
    Such WSGI applications will incur the least runtime overhead, however,
    they will share the same process space with other Apache modules such
    as PHP, as well as the process being used to serve up static file
    content. Running WSGI applications within the standard Apache child
    processes will also mean the application will run as the user that
    Apache would normally run as.

**%{ENV:variable}**

    The process group name will be set to the value of the named
    environment variable. The environment variable is looked-up via the
    internal Apache notes and subprocess environment data structures and
    (if not found there) via getenv() from the Apache server process.
    The result must identify a named process group setup using the
    WSGIDaemonProcess directive.

In an Apache configuration file, environment variables accessible using
the `%{ENV}` variable reference can be setup by using directives such as
SetEnv and RewriteRule.

For example, to select which process group a specific WSGI application
should execute within based on entries in a database file, the following
could be used::

    RewriteEngine On
    RewriteMap wsgiprocmap dbm:/etc/httpd/wsgiprocmap.dbm
    RewriteRule . - [E=PROCESS_GROUP:${wsgiprocmap:%{REQUEST_URI}}]

    WSGIProcessGroup %{ENV:PROCESS_GROUP}

Note that the WSGIDaemonProcess directive and corresponding features are
not available on Windows or when running Apache 1.3.
