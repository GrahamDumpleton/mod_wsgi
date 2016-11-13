=========================
Quick Configuration Guide
=========================

This document describes the steps for configuring mod_wsgi for a basic
WSGI application.

If you are setting up mod_wsgi for the very first time, it is highly
recommended that you follow the examples in this document. Make sure that
you at least get the examples running to verify that mod_wsgi is working
correctly before attempting to install any WSGI applications of your own.

WSGI Application Script File
----------------------------

WSGI is a specification of a generic API for mapping between an underlying
web server and a Python web application. WSGI itself is described by Python
PEP 3333:

  * http://www.python.org/dev/peps/pep-3333/
    
The purpose of the WSGI specification is to provide a common mechanism for
hosting a Python web application on a range of different web servers
supporting the Python programming language.

A very simple WSGI application, and the one which should be used for the
examples in this document, is as follows::

    def application(environ, start_response):
        status = '200 OK'
        output = b'Hello World!'

        response_headers = [('Content-type', 'text/plain'),
                            ('Content-Length', str(len(output)))]
        start_response(status, response_headers)

        return [output]

This sample application will need to be placed into what will be referred
to as the WSGI application script file. For the examples presented here,
the WSGI application will be run as the user that Apache runs as. As such,
the user that Apache runs as must have read access to both the WSGI
application script file and all the parent directories that contain it.

Note that mod_wsgi requires that the WSGI application entry point be called
'application'. If you want to call it something else then you would need to
configure mod_wsgi explicitly to use the other name. Thus, don't go
arbitrarily changing the name of the function. If you do, even if you set
up everything else correctly the application will not be found.

Mounting The WSGI Application
-----------------------------

There are a number of ways that a WSGI application hosted by mod_wsgi
can be mounted against a specific URL. These methods are similar to how
one would configure traditional CGI applications.

The main approach entails explicitly declaring in the main Apache
configuration file the URL mount point and a reference to the WSGI
application script file. In this case the mapping is fixed, with changes
only being able to be made by modifying the main Apache configuration and
restarting Apache.

When using mod_cgi to host CGI applications, this would be done using the
ScriptAlias directive. For mod_wsgi, the directive is instead called
WSGIScriptAlias::

    WSGIScriptAlias /myapp /usr/local/www/wsgi-scripts/myapp.wsgi

This directive can only appear in the main Apache configuration files. The
directive can be used at server scope but would normally be placed within
the VirtualHost container for a particular site. It cannot be used within
either of the Location, Directory or Files container directives, nor can it
be used within a ".htaccess" file.

The first argument to the WSGIScriptAlias directive should be the URL
mount point for the WSGI application. For this case the URL should not
contain a trailing slash. The only exception to this is if the WSGI
application is to be mounted at the root of the web server, in which case
'/' would be used.

The second argument to the WSGIScriptAlias directive should be an absolute
pathname to the WSGI application script file. It is into this file that
the sample WSGI application code should be placed.

Note that an absolute pathname must be used for the WSGI application script
file supplied as the second argument. It is not possible to specify an
application by Python module name alone. A full path is used for a number
of reasons, the main one being so that all the Apache access controls can
still be applied to indicate who can actually access the WSGI application.

Because the Apache access controls will apply, if the WSGI application is
located outside of any directories already configured to be accessible to
Apache, it will be necessary to tell Apache that files within that
directory can be used. To do this the Directory directive must be used::

    <Directory /usr/local/www/wsgi-scripts>
    Order allow,deny
    Allow from all
    </Directory>

Note that it is highly recommended that the WSGI application script file in
this case NOT be placed within the existing DocumentRoot for your main
Apache installation, or the particular site you are setting it up for. This
is because if that directory is otherwise being used as a source of static
files, the source code for your application might be able to be downloaded.

You also should not use the home directory of a user account, as to do
that would mean allowing Apache to serve up any files in that account. In
this case any misconfiguration of Apache could end up exposing your whole
account for downloading.

It is thus recommended that a special directory be setup distinct from
other directories and that the only thing in that directory be the WSGI
application script file, and if necessary any support files it requires.

A complete virtual host configuration for this type of setup would
therefore be something like::

    <VirtualHost *:80>

        ServerName www.example.com
        ServerAlias example.com
        ServerAdmin webmaster@example.com

        DocumentRoot /usr/local/www/documents

        <Directory /usr/local/www/documents>
        Order allow,deny
        Allow from all
        </Directory>

        WSGIScriptAlias /myapp /usr/local/www/wsgi-scripts/myapp.wsgi

        <Directory /usr/local/www/wsgi-scripts>
        Order allow,deny
        Allow from all
        </Directory>

    </VirtualHost>

After appropriate changes have been made Apache will need to be restarted.
For this example, the URL 'http://www.example.com/myapp' would then be used
to access the the WSGI application.

Note that you obviously should substitute the paths and hostname with
values appropriate for your system.

Mounting At Root Of Site
------------------------

If instead you want to mount a WSGI application at the root of a site,
simply list '/' as the mount point when configuring the WSGIScriptAlias
directive::

    WSGIScriptAlias / /usr/local/www/wsgi-scripts/myapp.wsgi

Do note however that doing so will mean that any static files contained in
the DocumentRoot will be hidden and requests against URLs pertaining to
the static files will instead be processed by the WSGI application.

In this situation it becomes necessary to remap using the Alias directive,
any URLs for static files to the directory containing them::

    Alias /robots.txt /usr/local/www/documents/robots.txt
    Alias /favicon.ico /usr/local/www/documents/favicon.ico

    Alias /media/ /usr/local/www/documents/media/

A complete virtual host configuration for this type of setup would
therefore be something like::

    <VirtualHost *:80>

        ServerName www.example.com
        ServerAlias example.com
        ServerAdmin webmaster@example.com

        DocumentRoot /usr/local/www/documents

        Alias /robots.txt /usr/local/www/documents/robots.txt
        Alias /favicon.ico /usr/local/www/documents/favicon.ico

        Alias /media/ /usr/local/www/documents/media/

        <Directory /usr/local/www/documents>
        Order allow,deny
        Allow from all
        </Directory>

        WSGIScriptAlias / /usr/local/www/wsgi-scripts/myapp.wsgi

        <Directory /usr/local/www/wsgi-scripts>
        Order allow,deny
        Allow from all
        </Directory>

    </VirtualHost>

After appropriate changes have been made Apache will need to be restarted.
For this example, the URL 'http://www.example.com/' would then be used
to access the the WSGI application.

Note that you obviously should substitute the paths and hostname with
values appropriate for your system.

Delegation To Daemon Process
----------------------------

By default any WSGI application will run in what is called embedded mode.
That is, the application will be hosted within the Apache worker processes
used to handle normal static file requests.

When embedded mode is used, whenever you make changes to your WSGI
application code you would generally have to restart the whole Apache web
server in order for changes to be picked up. This can be inconvenient,
especially if the web server is a shared resource hosting other web
applications at the same time, or you don't have root access to be able to
restart the server and rely on someone else to restart it.

On UNIX systems when running Apache 2.X, an option which exists with
mod_wsgi and that avoids the need to restart the whole Apache web server
when code changes are made, is to use what is called daemon mode.

In daemon mode a set of processes is created for hosting a WSGI application,
with any requests for that WSGI application automatically being routed to
those processes for handling.

When code changes are made and it is desired that the daemon processes for
the WSGI application be restarted, all that is required is to mark the WSGI
application script file as modified by using the 'touch' command.

To make use of daemon mode for WSGI applications hosted within a specific
site, the WSGIDaemonProcess and WSGIProcessGroup directives would need to
be defined. For example, to setup a daemon process group containing two
multithreaded process one could use::

    WSGIDaemonProcess example.com processes=2 threads=15
    WSGIProcessGroup example.com

A complete virtual host configuration for this type of setup would
therefore be something like::

    <VirtualHost *:80>

        ServerName www.example.com
        ServerAlias example.com
        ServerAdmin webmaster@example.com

        DocumentRoot /usr/local/www/documents

        Alias /robots.txt /usr/local/www/documents/robots.txt
        Alias /favicon.ico /usr/local/www/documents/favicon.ico

        Alias /media/ /usr/local/www/documents/media/

        <Directory /usr/local/www/documents>
        Order allow,deny
        Allow from all
        </Directory>

        WSGIDaemonProcess example.com processes=2 threads=15 display-name=%{GROUP}
        WSGIProcessGroup example.com

        WSGIScriptAlias / /usr/local/www/wsgi-scripts/myapp.wsgi

        <Directory /usr/local/www/wsgi-scripts>
        Order allow,deny
        Allow from all
        </Directory>

    </VirtualHost>

After appropriate changes have been made Apache will need to be restarted.
For this example, the URL 'http://www.example.com/' would then be used
to access the the WSGI application.

Note that you obviously should substitute the paths and hostname with
values appropriate for your system.

As mentioned previously, the daemon processes will be shutdown and restarted
automatically if the WSGI application script file is modified.

For the sample application presented in this document the whole application
is in that file. For more complicated applications the WSGI application
script file will be merely an entry point to an application being imported
from other Python modules or packages. In this later case, although no
change may be required to the WSGI application script file itself, it can
still be touched to trigger restarting of the daemon processes in the event
that any code in the separate modules or packages is changed.

Note that only requests for the WSGI application are handled within the
context of the daemon processes. Any requests for static files are still
handled within the Apache worker processes.

Debugging Any Problems
----------------------

To debug any problems one should take note of the type of error response
being returned, but more importantly one should look at the Apache error
logs for more detailed descriptions of a specific problem.

Being new to mod_wsgi it is highly recommended that the default Apache
LogLevel be increased from 'warn' to 'info'::

    LogLevel info

When this is done mod_wsgi will output additional information regarding
when daemon processes are created, when Python sub interpreters related
to a group of WSGI applications are created and when WSGI application
script files are loaded and/or reloaded. This information can be quite
valuable in determining what problem may be occuring.

Note that where the LogLevel directive may have been defined both in and
outside of a VirualHost directive, due to the VirtualHost declaring its
own error logs, both instances of the LogLevel directive should be changed.

This is because although the virtual host may have its own error log, some
information is still logged to the main Apache error log and the LogLevel
directive outside of the virtual host context needs to be changed for that
additional information to be recorded.

In other words, even if the VirtualHost has its own error log file, also
look in the main Apache error log file for information as well.
