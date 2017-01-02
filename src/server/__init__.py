from __future__ import print_function, division, absolute_import

import os
import sys
import shutil
import subprocess
import optparse
import math
import signal
import threading
import atexit
import imp
import re
import pprint
import time
import traceback
import locale

try:
    import Queue as queue
except ImportError:
    import queue

from . import apxs_config

_py_version = '%s%s' % sys.version_info[:2]
_py_soabi = ''
_py_soext = '.so'
_py_dylib = ''

try:
    import imp
    import sysconfig
    import distutils.sysconfig

    _py_soabi = sysconfig.get_config_var('SOABI')
    _py_soext = sysconfig.get_config_var('SO')

    if (sysconfig.get_config_var('WITH_DYLD') and
            sysconfig.get_config_var('LIBDIR') and
            sysconfig.get_config_var('LDLIBRARY')):
        _py_dylib = os.path.join(sysconfig.get_config_var('LIBDIR'),
                sysconfig.get_config_var('LDLIBRARY'))
        if not os.path.exists(_py_dylib):
            _py_dylib = ''

except ImportError:
    pass

MOD_WSGI_SO = 'mod_wsgi-py%s%s' % (_py_version, _py_soext)
MOD_WSGI_SO = os.path.join(os.path.dirname(__file__), MOD_WSGI_SO)

if not os.path.exists(MOD_WSGI_SO) and _py_soabi:
    MOD_WSGI_SO = 'mod_wsgi-py%s.%s%s' % (_py_version, _py_soabi, _py_soext)
    MOD_WSGI_SO = os.path.join(os.path.dirname(__file__), MOD_WSGI_SO)

if not os.path.exists(MOD_WSGI_SO) and os.name == 'nt':
    MOD_WSGI_SO = 'mod_wsgi%s' % distutils.sysconfig.get_config_var('EXT_SUFFIX')
    MOD_WSGI_SO = os.path.join(os.path.dirname(__file__), MOD_WSGI_SO)

def where():
    return MOD_WSGI_SO

def default_run_user():
    if os.name == 'nt':
        return '#0'

    try:
        import pwd
        uid = os.getuid()
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return '#%d' % uid

def default_run_group():
    if os.name == 'nt':
        return '#0'

    try:
        import pwd
        uid = os.getuid()
        entry = pwd.getpwuid(uid)
    except KeyError:
        return '#%d' % uid

    try:
        import grp
        gid = entry.pw_gid
        return grp.getgrgid(gid).gr_name
    except KeyError:
        return '#%d' % gid

def find_program(names, default=None, paths=[]):
    for name in names:
        for path in os.environ['PATH'].split(':') + paths:
            program = os.path.join(path, name)
            if os.path.exists(program):
                return program
    return default

def find_mimetypes():
    import mimetypes
    for name in mimetypes.knownfiles:
        if os.path.exists(name):
            return name
            break
    else:
        return name

APACHE_GENERAL_CONFIG = """
<IfModule !version_module>
LoadModule version_module '${MOD_WSGI_MODULES_DIRECTORY}/mod_version.so'
</IfModule>

ServerName %(host)s
ServerRoot '%(server_root)s'
PidFile '%(pid_file)s'

<IfVersion >= 2.4>
DefaultRuntimeDir '%(server_root)s'
</IfVersion>

ServerTokens ProductOnly
ServerSignature Off

User ${MOD_WSGI_USER}
Group ${MOD_WSGI_GROUP}

<IfDefine MOD_WSGI_WITH_LISTENER_HOST>
Listen %(host)s:%(port)s
</IfDefine>
<IfDefine !MOD_WSGI_WITH_LISTENER_HOST>
Listen %(port)s
</IfDefine>

<IfVersion < 2.4>
LockFile '%(server_root)s/accept.lock'
</IfVersion>

<IfVersion >= 2.4>
<IfDefine MOD_WSGI_WITH_PHP5>
<IfModule !mpm_event_module>
<IfModule !mpm_worker_module>
<IfModule !mpm_prefork_module>
<IfDefine MOD_WSGI_MPM_EXISTS_PREFORK_MODULE>
LoadModule mpm_prefork_module '${MOD_WSGI_MODULES_DIRECTORY}/mod_mpm_prefork.so'
</IfDefine>
</IfModule>
</IfModule>
</IfModule>
</IfDefine>
</IfVersion>

<IfVersion >= 2.4>
<IfModule !mpm_event_module>
<IfModule !mpm_worker_module>
<IfModule !mpm_prefork_module>
<IfDefine MOD_WSGI_MPM_ENABLE_EVENT_MODULE>
LoadModule mpm_event_module '${MOD_WSGI_MODULES_DIRECTORY}/mod_mpm_event.so'
</IfDefine>
<IfDefine MOD_WSGI_MPM_ENABLE_WORKER_MODULE>
LoadModule mpm_worker_module '${MOD_WSGI_MODULES_DIRECTORY}/mod_mpm_worker.so'
</IfDefine>
<IfDefine MOD_WSGI_MPM_ENABLE_PREFORK_MODULE>
LoadModule mpm_prefork_module '${MOD_WSGI_MODULES_DIRECTORY}/mod_mpm_prefork.so'
</IfDefine>
</IfModule>
</IfModule>
</IfModule>
</IfVersion>

<IfDefine MOD_WSGI_WITH_HTTP2>
LoadModule http2_module '${MOD_WSGI_MODULES_DIRECTORY}/mod_http2.so'
</IfDefine>

<IfVersion >= 2.4>
<IfModule !access_compat_module>
LoadModule access_compat_module '${MOD_WSGI_MODULES_DIRECTORY}/mod_access_compat.so'
</IfModule>
<IfModule !unixd_module>
LoadModule unixd_module '${MOD_WSGI_MODULES_DIRECTORY}/mod_unixd.so'
</IfModule>
<IfModule !authn_core_module>
LoadModule authn_core_module '${MOD_WSGI_MODULES_DIRECTORY}/mod_authn_core.so'
</IfModule>
<IfModule !authz_core_module>
LoadModule authz_core_module '${MOD_WSGI_MODULES_DIRECTORY}/mod_authz_core.so'
</IfModule>
</IfVersion>

<IfModule !authz_host_module>
LoadModule authz_host_module '${MOD_WSGI_MODULES_DIRECTORY}/mod_authz_host.so'
</IfModule>
<IfModule !mime_module>
LoadModule mime_module '${MOD_WSGI_MODULES_DIRECTORY}/mod_mime.so'
</IfModule>
<IfModule !rewrite_module>
LoadModule rewrite_module '${MOD_WSGI_MODULES_DIRECTORY}/mod_rewrite.so'
</IfModule>
<IfModule !alias_module>
LoadModule alias_module '${MOD_WSGI_MODULES_DIRECTORY}/mod_alias.so'
</IfModule>
<IfModule !dir_module>
LoadModule dir_module '${MOD_WSGI_MODULES_DIRECTORY}/mod_dir.so'
</IfModule>
<IfModule !env_module>
LoadModule env_module '${MOD_WSGI_MODULES_DIRECTORY}/mod_env.so'
</IfModule>
<IfModule !headers_module>
LoadModule headers_module '${MOD_WSGI_MODULES_DIRECTORY}/mod_headers.so'
</IfModule>
<IfModule !filter_module>
LoadModule filter_module '${MOD_WSGI_MODULES_DIRECTORY}/mod_filter.so'
</IfModule>

<IfDefine MOD_WSGI_DIRECTORY_LISTING>
<IfModule !autoindex_module>
LoadModule autoindex_module '${MOD_WSGI_MODULES_DIRECTORY}/mod_autoindex.so'
</IfModule>
</IfDefine>

<IfVersion >= 2.2.15>
<IfModule !reqtimeout_module>
LoadModule reqtimeout_module '${MOD_WSGI_MODULES_DIRECTORY}/mod_reqtimeout.so'
</IfModule>
</IfVersion>

<IfDefine MOD_WSGI_COMPRESS_RESPONSES>
<IfModule !deflate_module>
LoadModule deflate_module '${MOD_WSGI_MODULES_DIRECTORY}/mod_deflate.so'
</IfModule>
</IfDefine>

<IfDefine MOD_WSGI_AUTH_USER>
<IfModule !auth_basic_module>
LoadModule auth_basic_module '${MOD_WSGI_MODULES_DIRECTORY}/mod_auth_basic.so'
</IfModule>
<IfModule !auth_digest_module>
LoadModule auth_digest_module '${MOD_WSGI_MODULES_DIRECTORY}/mod_auth_digest.so'
</IfModule>
<IfModule !authz_user_module>
LoadModule authz_user_module '${MOD_WSGI_MODULES_DIRECTORY}/mod_authz_user.so'
</IfModule>
</IfDefine>

<IfDefine MOD_WSGI_WITH_PROXY>
<IfModule !proxy_module>
LoadModule proxy_module ${MOD_WSGI_MODULES_DIRECTORY}/mod_proxy.so
</IfModule>
<IfModule !proxy_http_module>
LoadModule proxy_http_module ${MOD_WSGI_MODULES_DIRECTORY}/mod_proxy_http.so
</IfModule>
</IfDefine>

<IfModule mpm_prefork_module>
<IfDefine MOD_WSGI_WITH_PHP5>
<IfModule !php5_module>
Loadmodule php5_module '${MOD_WSGI_MODULES_DIRECTORY}/libphp5.so'
</IfModule>
AddHandler application/x-httpd-php .php
</IfDefine>
</IfModule>

<IfDefine MOD_WSGI_LOAD_PYTHON_DYLIB>
LoadFile '%(python_dylib)s'
</IfDefine>

LoadModule wsgi_module '%(mod_wsgi_so)s'

<IfDefine MOD_WSGI_SERVER_METRICS>
<IfModule !status_module>
LoadModule status_module '${MOD_WSGI_MODULES_DIRECTORY}/mod_status.so'
</IfModule>
</IfDefine>

<IfDefine MOD_WSGI_CGID_SCRIPT>
<IfModule !cgid_module>
LoadModule cgid_module '${MOD_WSGI_MODULES_DIRECTORY}/mod_cgid.so'
</IfModule>
</IfDefine>

<IfDefine MOD_WSGI_CGI_SCRIPT>
<IfModule !cgi_module>
LoadModule cgi_module '${MOD_WSGI_MODULES_DIRECTORY}/mod_cgi.so'
</IfModule>
</IfDefine>

<IfVersion < 2.4>
DefaultType text/plain
</IfVersion>

TypesConfig '%(mime_types)s'

HostnameLookups Off
MaxMemFree 64
Timeout %(socket_timeout)s
ListenBacklog %(server_backlog)s

<IfDefine MOD_WSGI_WITH_HTTP2>
Protocols h2 h2c http/1.1
</IfDefine>

<IfVersion >= 2.2.15>
RequestReadTimeout %(request_read_timeout)s
</IfVersion>

LimitRequestBody %(limit_request_body)s

<Directory />
    AllowOverride None
<IfVersion < 2.4>
    Order deny,allow
    Deny from all
</IfVersion>
<IfVersion >= 2.4>
    Require all denied
</IfVersion>
</Directory>

WSGIPythonHome '%(python_home)s'

WSGIVerboseDebugging '%(verbose_debugging_flag)s'

<IfDefine !ONE_PROCESS>
WSGIRestrictEmbedded On
WSGISocketPrefix %(server_root)s/wsgi
<IfDefine MOD_WSGI_MULTIPROCESS>
WSGIDaemonProcess %(host)s:%(port)s \\
   display-name='%(daemon_name)s' \\
   home='%(working_directory)s' \\
   processes=%(processes)s \\
   threads=%(threads)s \\
   maximum-requests=%(maximum_requests)s \\
   python-path='%(python_path)s' \\
   python-eggs='%(python_eggs)s' \\
   lang='%(lang)s' \\
   locale='%(locale)s' \\
   listen-backlog=%(daemon_backlog)s \\
   queue-timeout=%(queue_timeout)s \\
   socket-timeout=%(socket_timeout)s \\
   connect-timeout=%(connect_timeout)s \\
   request-timeout=%(request_timeout)s \\
   inactivity-timeout=%(inactivity_timeout)s \\
   startup-timeout=%(startup_timeout)s \\
   deadlock-timeout=%(deadlock_timeout)s \\
   graceful-timeout=%(graceful_timeout)s \\
   eviction-timeout=%(eviction_timeout)s \\
   restart-interval=%(restart_interval)s \\
   shutdown-timeout=%(shutdown_timeout)s \\
   send-buffer-size=%(send_buffer_size)s \\
   receive-buffer-size=%(receive_buffer_size)s \\
   header-buffer-size=%(header_buffer_size)s \\
   response-buffer-size=%(response_buffer_size)s \\
   server-metrics=%(server_metrics_flag)s
</IfDefine>
<IfDefine !MOD_WSGI_MULTIPROCESS>
WSGIDaemonProcess %(host)s:%(port)s \\
   display-name='%(daemon_name)s' \\
   home='%(working_directory)s' \\
   threads=%(threads)s \\
   maximum-requests=%(maximum_requests)s \\
   python-path='%(python_path)s' \\
   python-eggs='%(python_eggs)s' \\
   lang='%(lang)s' \\
   locale='%(locale)s' \\
   listen-backlog=%(daemon_backlog)s \\
   queue-timeout=%(queue_timeout)s \\
   socket-timeout=%(socket_timeout)s \\
   connect-timeout=%(connect_timeout)s \\
   request-timeout=%(request_timeout)s \\
   inactivity-timeout=%(inactivity_timeout)s \\
   startup-timeout=%(startup_timeout)s \\
   deadlock-timeout=%(deadlock_timeout)s \\
   graceful-timeout=%(graceful_timeout)s \\
   eviction-timeout=%(eviction_timeout)s \\
   restart-interval=%(restart_interval)s \\
   shutdown-timeout=%(shutdown_timeout)s \\
   send-buffer-size=%(send_buffer_size)s \\
   receive-buffer-size=%(receive_buffer_size)s \\
   response-buffer-size=%(response_buffer_size)s \\
   server-metrics=%(server_metrics_flag)s
</IfDefine>
</IfDefine>

WSGICallableObject '%(callable_object)s'
WSGIPassAuthorization On
WSGIMapHEADToGET %(map_head_to_get)s

<IfDefine ONE_PROCESS>
WSGIRestrictStdin Off
<IfDefine MOD_WSGI_WITH_PYTHON_PATH>
WSGIPythonPath '%(python_path)s'
</IfDefine>
</IfDefine>

<IfDefine MOD_WSGI_SERVER_METRICS>
ExtendedStatus On
</IfDefine>

WSGIServerMetrics %(server_metrics_flag)s

<IfDefine MOD_WSGI_SERVER_STATUS>
<Location /server-status>
    SetHandler server-status
<IfVersion < 2.4>
    Order deny,allow
    Deny from all
    Allow from localhost
</IfVersion>
<IfVersion >= 2.4>
    Require all denied
    Require host localhost
</IfVersion>
</Location>
</IfDefine>

<IfDefine MOD_WSGI_KEEP_ALIVE>
KeepAlive On
KeepAliveTimeout %(keep_alive_timeout)s
</IfDefine>
<IfDefine !MOD_WSGI_KEEP_ALIVE>
KeepAlive Off
</IfDefine>

<IfDefine MOD_WSGI_COMPRESS_RESPONSES>
AddOutputFilterByType DEFLATE text/plain
AddOutputFilterByType DEFLATE text/html
AddOutputFilterByType DEFLATE text/xml
AddOutputFilterByType DEFLATE text/css
AddOutputFilterByType DEFLATE text/javascript
AddOutputFilterByType DEFLATE application/xhtml+xml
AddOutputFilterByType DEFLATE application/javascript
</IfDefine>

<IfDefine MOD_WSGI_ROTATE_LOGS>
ErrorLog "|%(rotatelogs_executable)s \\
    %(error_log_file)s.%%Y-%%m-%%d-%%H_%%M_%%S %(max_log_size)sM"
</IfDefine>
<IfDefine !MOD_WSGI_ROTATE_LOGS>
ErrorLog "%(error_log_file)s"
</IfDefine>
LogLevel %(log_level)s

<IfDefine MOD_WSGI_ERROR_LOG_FORMAT>
ErrorLogFormat "%(error_log_format)s"
</IfDefine>

<IfDefine MOD_WSGI_ACCESS_LOG>
<IfModule !log_config_module>
LoadModule log_config_module ${MOD_WSGI_MODULES_DIRECTORY}/mod_log_config.so
</IfModule>
LogFormat "%%h %%l %%u %%t \\"%%r\\" %%>s %%b" common
LogFormat "%%h %%l %%u %%t \\"%%r\\" %%>s %%b \\"%%{Referer}i\\" \\"%%{User-agent}i\\"" combined
LogFormat "%(access_log_format)s" custom
<IfDefine MOD_WSGI_ROTATE_LOGS>
CustomLog "|%(rotatelogs_executable)s \\
    %(access_log_file)s.%%Y-%%m-%%d-%%H_%%M_%%S %(max_log_size)sM" %(log_format_nickname)s
</IfDefine>
<IfDefine !MOD_WSGI_ROTATE_LOGS>
CustomLog "%(access_log_file)s" %(log_format_nickname)s
</IfDefine>
</IfDefine>

<IfDefine MOD_WSGI_CHUNKED_REQUEST>
WSGIChunkedRequest On
</IfDefine>

<IfDefine MOD_WSGI_WITH_PROXY_HEADERS>
WSGITrustedProxyHeaders %(trusted_proxy_headers)s
</IfDefine>
<IfDefine MOD_WSGI_WITH_TRUSTED_PROXIES>
WSGITrustedProxies %(trusted_proxies)s
</IfDefine>

<IfDefine MOD_WSGI_WITH_HTTPS>
<IfModule !ssl_module>
LoadModule ssl_module ${MOD_WSGI_MODULES_DIRECTORY}/mod_ssl.so
</IfModule>
</IfDefine>

<IfModule mpm_prefork_module>
<IfDefine !ONE_PROCESS>
ServerLimit %(prefork_server_limit)s
StartServers %(prefork_start_servers)s
MaxClients %(prefork_max_clients)s
MinSpareServers %(prefork_min_spare_servers)s
MaxSpareServers %(prefork_max_spare_servers)s
</IfDefine>
<IfDefine ONE_PROCESS>
ServerLimit 1
StartServers 1
MaxClients 1
MinSpareServers 1
MaxSpareServers 1
</IfDefine>
MaxRequestsPerChild 0
</IfModule>

<IfModule mpm_worker_module>
<IfDefine !ONE_PROCESS>
ServerLimit %(worker_server_limit)s
ThreadLimit %(worker_thread_limit)s
StartServers %(worker_start_servers)s
MaxClients %(worker_max_clients)s
MinSpareThreads %(worker_min_spare_threads)s
MaxSpareThreads %(worker_max_spare_threads)s
ThreadsPerChild %(worker_threads_per_child)s
</IfDefine>
<IfDefine ONE_PROCESS>
ServerLimit 1
ThreadLimit 1
StartServers 1 
MaxClients 1
MinSpareThreads 1
MaxSpareThreads 1
ThreadsPerChild 1
</IfDefine>
MaxRequestsPerChild 0
ThreadStackSize 262144
</IfModule>

<IfModule mpm_event_module>
<IfDefine !ONE_PROCESS>
ServerLimit %(worker_server_limit)s
ThreadLimit %(worker_thread_limit)s
StartServers %(worker_start_servers)s
MaxClients %(worker_max_clients)s
MinSpareThreads %(worker_min_spare_threads)s
MaxSpareThreads %(worker_max_spare_threads)s
ThreadsPerChild %(worker_threads_per_child)s
</IfDefine>
<IfDefine ONE_PROCESS>
ServerLimit 1
ThreadLimit 1
StartServers 1
MaxClients 1
MinSpareThreads 1
MaxSpareThreads 1
ThreadsPerChild 1
</IfDefine>
MaxRequestsPerChild 0
ThreadStackSize 262144
</IfModule>

<IfDefine !MOD_WSGI_VIRTUAL_HOST>
<IfVersion < 2.4>
NameVirtualHost *:%(port)s
</IfVersion>
<VirtualHost _default_:%(port)s>
</VirtualHost>
</IfDefine>

<IfDefine MOD_WSGI_VIRTUAL_HOST>

<IfVersion < 2.4>
NameVirtualHost *:%(port)s
</IfVersion>
<VirtualHost _default_:%(port)s>
<Location />
<IfVersion < 2.4>
Order deny,allow
Deny from all
</IfVersion>
<IfVersion >= 2.4>
Require all denied
</IfVersion>
<IfDefine MOD_WSGI_ALLOW_LOCALHOST>
Allow from localhost
</IfDefine>
</Location>
</VirtualHost>
<IfDefine !MOD_WSGI_HTTPS_ONLY>
<VirtualHost *:%(port)s>
ServerName %(server_name)s
<IfDefine MOD_WSGI_SERVER_ALIAS>
ServerAlias %(server_aliases)s
</IfDefine>
</VirtualHost>
<IfDefine MOD_WSGI_REDIRECT_WWW>
<VirtualHost *:%(port)s>
ServerName %(parent_domain)s
Redirect permanent / http://%(server_name)s:%(port)s/
</VirtualHost>
</IfDefine>
</IfDefine>

<IfDefine MOD_WSGI_HTTPS_ONLY>
<VirtualHost *:%(port)s>
ServerName %(server_name)s
<IfDefine MOD_WSGI_SERVER_ALIAS>
ServerAlias %(server_aliases)s
</IfDefine>
RewriteEngine On
RewriteCond %%{HTTPS} off
RewriteRule (.*) https://%(server_name)s:%(https_port)s%%{REQUEST_URI}
</VirtualHost>
<IfDefine MOD_WSGI_REDIRECT_WWW>
<VirtualHost *:%(port)s>
ServerName %(parent_domain)s
RewriteEngine On
RewriteCond %%{HTTPS} off
RewriteRule (.*) https://%(server_name)s:%(https_port)s%%{REQUEST_URI}
</VirtualHost>
</IfDefine>
</IfDefine>

</IfDefine>

<IfDefine MOD_WSGI_VIRTUAL_HOST>

<IfDefine MOD_WSGI_WITH_HTTPS>
<IfDefine MOD_WSGI_WITH_LISTENER_HOST>
Listen %(host)s:%(https_port)s
</IfDefine>
<IfDefine !MOD_WSGI_WITH_LISTENER_HOST>
Listen %(https_port)s
</IfDefine>
<IfVersion < 2.4>
NameVirtualHost *:%(https_port)s
</IfVersion>
<VirtualHost _default_:%(https_port)s>
<Location />
<IfVersion < 2.4>
Order deny,allow
Deny from all
</IfVersion>
<IfVersion >= 2.4>
Require all denied
</IfVersion>
<IfDefine MOD_WSGI_ALLOW_LOCALHOST>
Allow from localhost
</IfDefine>
</Location>
SSLEngine On
SSLCertificateFile %(ssl_certificate_file)s
SSLCertificateKeyFile %(ssl_certificate_key_file)s
<IfDefine MOD_WSGI_VERIFY_CLIENT>
SSLCACertificateFile %(ssl_ca_certificate_file)s
SSLVerifyClient none
</IfDefine>
<IfDefine MOD_WSGI_CERTIFICATE_CHAIN>
SSLCertificateChainFile %(ssl_certificate_chain_file)s
</IfDefine>
</VirtualHost>
<VirtualHost *:%(https_port)s>
ServerName %(server_name)s
<IfDefine MOD_WSGI_SERVER_ALIAS>
ServerAlias %(server_aliases)s
</IfDefine>
SSLEngine On
SSLCertificateFile %(ssl_certificate_file)s
SSLCertificateKeyFile %(ssl_certificate_key_file)s
<IfDefine MOD_WSGI_VERIFY_CLIENT>
SSLCACertificateFile %(ssl_ca_certificate_file)s
SSLVerifyClient none
</IfDefine>
<IfDefine MOD_WSGI_CERTIFICATE_CHAIN>
SSLCertificateChainFile %(ssl_certificate_chain_file)s
</IfDefine>
<IfDefine MOD_WSGI_HTTPS_ONLY>
<IfDefine MOD_WSGI_HSTS_POLICY>
Header set Strict-Transport-Security %(hsts_policy)s
</IfDefine>
</IfDefine>
<IfDefine MOD_WSGI_SSL_ENVIRONMENT>
SSLOptions +StdEnvVars
</IfDefine>
</VirtualHost>
<IfDefine MOD_WSGI_REDIRECT_WWW>
<VirtualHost *:%(https_port)s>
ServerName %(parent_domain)s
Redirect permanent / https://%(server_name)s:%(https_port)s/
SSLEngine On
SSLCertificateFile %(ssl_certificate_file)s
SSLCertificateKeyFile %(ssl_certificate_key_file)s
<IfDefine MOD_WSGI_VERIFY_CLIENT>
SSLCACertificateFile %(ssl_ca_certificate_file)s
SSLVerifyClient none
</IfDefine>
<IfDefine MOD_WSGI_CERTIFICATE_CHAIN>
SSLCertificateChainFile %(ssl_certificate_chain_file)s
</IfDefine>
</VirtualHost>
</IfDefine>
</IfDefine>

</IfDefine>

DocumentRoot '%(document_root)s'

<Directory '%(server_root)s'>
<Files handler.wsgi>
<IfVersion < 2.4>
    Order allow,deny
    Allow from all
</IfVersion>
<IfVersion >= 2.4>
    Require all granted
</IfVersion>
</Files>
</Directory>

<Directory '%(document_root)s%(mount_point)s'>
<IfDefine MOD_WSGI_DIRECTORY_INDEX>
    DirectoryIndex %(directory_index)s
</IfDefine>
<IfDefine MOD_WSGI_DIRECTORY_LISTING>
    Options +Indexes
</IfDefine>
<IfDefine MOD_WSGI_CGI_SCRIPT>
    Options +ExecCGI
</IfDefine>
<IfDefine MOD_WSGI_CGID_SCRIPT>
    Options +ExecCGI
</IfDefine>
    RewriteEngine On
    Include %(rewrite_rules)s
<IfDefine !MOD_WSGI_STATIC_ONLY>
    RewriteCond %%{REQUEST_FILENAME} !-f
<IfDefine MOD_WSGI_DIRECTORY_INDEX>
    RewriteCond %%{REQUEST_FILENAME} !-d
</IfDefine>
<IfDefine MOD_WSGI_SERVER_STATUS>
    RewriteCond %%{REQUEST_URI} !/server-status
</IfDefine>
    RewriteRule .* - [H=wsgi-handler]
</IfDefine>
<IfVersion < 2.4>
    Order allow,deny
    Allow from all
</IfVersion>
<IfVersion >= 2.4>
    Require all granted
</IfVersion>
</Directory>

<IfDefine MOD_WSGI_ERROR_OVERRIDE>
WSGIErrorOverride On
</IfDefine>

<IfDefine MOD_WSGI_HOST_ACCESS>
<Location />
    WSGIAccessScript '%(host_access_script)s'
</Location>
</IfDefine>

<IfDefine MOD_WSGI_AUTH_USER>
<Location />
    AuthType %(auth_type)s
    AuthName '%(host)s:%(port)s'
    Auth%(auth_type)sProvider wsgi
    WSGIAuthUserScript '%(auth_user_script)s'
<IfDefine MOD_WSGI_AUTH_GROUP>
    WSGIAuthGroupScript '%(auth_group_script)s'
</IfDefine>
<IfVersion < 2.4>
    Require valid-user
<IfDefine MOD_WSGI_AUTH_GROUP>
    Require wsgi-group '%(auth_group)s'
</IfDefine>
</IfVersion>
<IfVersion >= 2.4>
    <RequireAll>
    Require valid-user
<IfDefine MOD_WSGI_AUTH_GROUP>
    Require wsgi-group '%(auth_group)s'
</IfDefine>
    </RequireAll>
</IfVersion>
</Location>
</IfDefine>

<IfDefine !ONE_PROCESS>
WSGIHandlerScript wsgi-handler '%(server_root)s/handler.wsgi' \\
    process-group='%(host)s:%(port)s' application-group=%%{GLOBAL}
WSGIImportScript '%(server_root)s/handler.wsgi' \\
    process-group='%(host)s:%(port)s' application-group=%%{GLOBAL}
</IfDefine>

<IfDefine ONE_PROCESS>
WSGIHandlerScript wsgi-handler '%(server_root)s/handler.wsgi' \\
    process-group='%%{GLOBAL}' application-group=%%{GLOBAL}
WSGIImportScript '%(server_root)s/handler.wsgi' \\
    process-group='%%{GLOBAL}' application-group=%%{GLOBAL}
</IfDefine>
"""

APACHE_IGNORE_ACTIVITY_CONFIG = """
<Location '%(url)s'>
WSGIIgnoreActivity On
</Location>
"""

APACHE_PROXY_PASS_MOUNT_POINT_CONFIG = """
ProxyPass '%(mount_point)s' '%(url)s'
ProxyPassReverse '%(mount_point)s' '%(url)s'
<Location '%(mount_point)s'>
RewriteEngine On
RewriteRule .* - [E=SERVER_PORT:%%{SERVER_PORT},NE]
RequestHeader set X-Forwarded-Port %%{SERVER_PORT}e
RewriteCond %%{HTTPS} on
RewriteRule .* - [E=URL_SCHEME:https,NE]
RequestHeader set X-Forwarded-Scheme %%{URL_SCHEME}e env=URL_SCHEME
</Location>
"""

APACHE_PROXY_PASS_MOUNT_POINT_SLASH_CONFIG = """
ProxyPass '%(mount_point)s/' '%(url)s/'
ProxyPassReverse '%(mount_point)s/' '%(url)s/'
<Location '%(mount_point)s/'>
RewriteEngine On
RewriteRule .* - [E=SERVER_PORT:%%{SERVER_PORT},NE]
RequestHeader set X-Forwarded-Port %%{SERVER_PORT}e
RewriteCond %%{HTTPS} on
RewriteRule .* - [E=URL_SCHEME:https,NE]
RequestHeader set X-Forwarded-Scheme %%{URL_SCHEME}e env=URL_SCHEME
</Location>
<LocationMatch '^%(mount_point)s$'>
RewriteEngine On
RewriteRule - http://%%{HTTP_HOST}%%{REQUEST_URI}/ [R=302,L]
</LocationMatch>
"""

APACHE_PROXY_PASS_HOST_CONFIG = """
<VirtualHost *:%(port)s>
ServerName %(host)s
ProxyPass / '%(url)s'
ProxyPassReverse / '%(url)s'
RequestHeader set X-Forwarded-Port %(port)s
RewriteEngine On
RewriteCond %%{HTTPS} on
RewriteRule .* - [E=URL_SCHEME:https,NE]
RequestHeader set X-Forwarded-Scheme %%{URL_SCHEME}e env=URL_SCHEME
</VirtualHost>
"""

APACHE_ALIAS_DIRECTORY_CONFIG = """
Alias '%(mount_point)s' '%(directory)s'

<Directory '%(directory)s'>
<IfVersion < 2.4>
    Order allow,deny
    Allow from all
</IfVersion>
<IfVersion >= 2.4>
    Require all granted
</IfVersion>
</Directory>
"""

APACHE_ALIAS_FILENAME_CONFIG = """
Alias '%(mount_point)s' '%(directory)s/%(filename)s'

<Directory '%(directory)s'>
<Files '%(filename)s'>
<IfVersion < 2.4>
    Order allow,deny
    Allow from all
</IfVersion>
<IfVersion >= 2.4>
    Require all granted
</IfVersion>
</Files>
</Directory>
"""

APACHE_ALIAS_DOCUMENTATION = """
Alias /__wsgi__/docs '%(documentation_directory)s'
Alias /__wsgi__/images '%(images_directory)s'

<Directory '%(documentation_directory)s'>
    DirectoryIndex index.html
<IfVersion < 2.4>
    Order allow,deny
    Allow from all
</IfVersion>
<IfVersion >= 2.4>
    Require all granted
</IfVersion>
</Directory>

<Directory '%(images_directory)s'>
<IfVersion < 2.4>
    Order allow,deny
    Allow from all
</IfVersion>
<IfVersion >= 2.4>
    Require all granted
</IfVersion>
</Directory>
"""

APACHE_VERIFY_CLIENT_CONFIG = """
<IfDefine MOD_WSGI_VERIFY_CLIENT>
<Location '%(path)s'>
SSLVerifyClient require
SSLVerifyDepth 1
</Location>
</IfDefine>
"""

APACHE_ERROR_DOCUMENT_CONFIG = """
ErrorDocument '%(status)s' '%(document)s'
"""

APACHE_SETENV_CONFIG = """
SetEnv '%(name)s' '%(value)s'
"""

APACHE_PASSENV_CONFIG = """
PassEnv '%(name)s'
"""

APACHE_HANDLER_SCRIPT_CONFIG = """
WSGIHandlerScript wsgi-resource '%(server_root)s/resource.wsgi' \\
    process-group='%(host)s:%(port)s' application-group=%%{GLOBAL}
"""

APACHE_HANDLER_CONFIG = """
AddHandler %(handler)s %(extension)s
"""

APACHE_INCLUDE_CONFIG = """
Include '%(filename)s'
"""

APACHE_TOOLS_CONFIG = """
WSGIDaemonProcess express display-name=%%{GROUP} threads=1 server-metrics=On
"""

APACHE_METRICS_CONFIG = """
WSGIImportScript '%(server_root)s/server-metrics.py' \\
    process-group=express application-group=server-metrics
"""

APACHE_SERVICE_CONFIG = """
WSGIDaemonProcess 'service:%(name)s' \\
    display-name=%%{GROUP} \\
    user='%(user)s' \\
    group='%(group)s' \\
    home='%(working_directory)s' \\
    threads=1 \\
    python-path='%(python_path)s' \\
    python-eggs='%(python_eggs)s' \\
    lang='%(lang)s' \\
    locale='%(locale)s' \\
    server-metrics=%(server_metrics_flag)s
WSGIImportScript '%(script)s' \\
    process-group='service:%(name)s' \\
    application-group=%%{GLOBAL}
"""

APACHE_SERVICE_WITH_LOG_CONFIG = """
<VirtualHost *:%(port)s>
<IfDefine MOD_WSGI_ROTATE_LOGS>
ErrorLog "|%(rotatelogs_executable)s \\
    %(log_directory)s/%(log_file)s.%%Y-%%m-%%d-%%H_%%M_%%S %(max_log_size)sM"
</IfDefine>
<IfDefine !MOD_WSGI_ROTATE_LOGS>
ErrorLog "%(log_directory)s/%(log_file)s"
</IfDefine>
WSGIDaemonProcess 'service:%(name)s' \\
    display-name=%%{GROUP} \\
    user='%(user)s' \\
    group='%(group)s' \\
    home='%(working_directory)s' \\
    threads=1 \\
    python-path='%(python_path)s' \\
    python-eggs='%(python_eggs)s' \\
    lang='%(lang)s' \\
    locale='%(locale)s' \\
    server-metrics=%(server_metrics_flag)s
WSGIImportScript '%(script)s' \\
    process-group='service:%(name)s' \\
    application-group=%%{GLOBAL}
</VirtualHost>
"""

def generate_apache_config(options):
    with open(options['httpd_conf'], 'w') as fp:
        print(APACHE_GENERAL_CONFIG % options, file=fp)

        if options['ignore_activity']:
            for url in options['ignore_activity']:
                print(APACHE_IGNORE_ACTIVITY_CONFIG % dict(url=url), file=fp)

        if options['proxy_mount_points']:
            for mount_point, url in options['proxy_mount_points']:
                if mount_point.endswith('/'):
                    print(APACHE_PROXY_PASS_MOUNT_POINT_CONFIG % dict(
                            mount_point=mount_point, url=url), file=fp)
                else:
                    print(APACHE_PROXY_PASS_MOUNT_POINT_SLASH_CONFIG % dict(
                            mount_point=mount_point, url=url), file=fp)

        if options['proxy_virtual_hosts']:
            for host, url in options['proxy_virtual_hosts']:
                print(APACHE_PROXY_PASS_HOST_CONFIG % dict(
                        host=host, port=options['port'], url=url),
                        file=fp)

        if options['url_aliases']:
            for mount_point, target in sorted(options['url_aliases'],
                    reverse=True):
                path = os.path.abspath(target)

                if os.path.isdir(path):
                    if target.endswith('/') and path != '/':
                        directory = path + '/'
                    else:
                        directory = path

                    print(APACHE_ALIAS_DIRECTORY_CONFIG % dict(
                            mount_point=mount_point, directory=directory),
                            file=fp)

                else:
                    directory = os.path.dirname(path)
                    filename = os.path.basename(path)

                    print(APACHE_ALIAS_FILENAME_CONFIG % dict(
                            mount_point=mount_point, directory=directory,
                            filename=filename), file=fp)

        if options['enable_docs']:
            print(APACHE_ALIAS_DOCUMENTATION % options, file=fp)

        if options['error_documents']:
            for status, document in options['error_documents']:
                print(APACHE_ERROR_DOCUMENT_CONFIG % dict(status=status,
                        document=document.replace("'", "\\'")), file=fp)

        if options['ssl_verify_client_urls']:
            paths = sorted(options['ssl_verify_client_urls'], reverse=True)
            for path in paths:
                print(APACHE_VERIFY_CLIENT_CONFIG % dict(path=path), file=fp)
        else:
            print(APACHE_VERIFY_CLIENT_CONFIG % dict(path='/'), file=fp)

        if options['setenv_variables']:
            for name, value in options['setenv_variables']:
                print(APACHE_SETENV_CONFIG % dict(name=name, value=value),
                        file=fp)

        if options['passenv_variables']:
            for name in options['passenv_variables']:
                print(APACHE_PASSENV_CONFIG % dict(name=name), file=fp)

        if options['handler_scripts']:
            print(APACHE_HANDLER_SCRIPT_CONFIG % options, file=fp)

            for extension, script in options['handler_scripts']:
                print(APACHE_HANDLER_CONFIG % dict(handler='wsgi-resource',
                        extension=extension), file=fp)

        if options['with_cgi']:
            print(APACHE_HANDLER_CONFIG % dict(handler='cgi-script',
                    extension='.cgi'), file=fp)

        if options['service_scripts']:
            service_log_files = {}
            if options['service_log_files']:
                service_log_files.update(options['service_log_files'])
            users = dict(options['service_users'] or [])
            groups = dict(options['service_groups'] or [])
            for name, script in options['service_scripts']:
                user = users.get(name, '${MOD_WSGI_USER}')
                group = groups.get(name, '${MOD_WSGI_GROUP}')
                if name in service_log_files:
                    print(APACHE_SERVICE_WITH_LOG_CONFIG % dict(name=name,
                            user=user, group=group, script=script,
                            port=options['port'],
                            log_directory=options['log_directory'],
                            log_file=service_log_files[name],
                            rotatelogs_executable=options['rotatelogs_executable'],
                            max_log_size=options['max_log_size'],
                            python_path=options['python_path'],
                            working_directory=options['working_directory'],
                            python_eggs=options['python_eggs'],
                            lang=options['lang'], locale=options['locale'],
                            server_metrics_flag=options['server_metrics_flag']),
                            file=fp)
                else:
                    print(APACHE_SERVICE_CONFIG % dict(name=name, user=user,
                            group=group, script=script,
                            python_path=options['python_path'],
                            working_directory=options['working_directory'],
                            python_eggs=options['python_eggs'],
                            lang=options['lang'], locale=options['locale'],
                            server_metrics_flag=options['server_metrics_flag']),
                            file=fp)

        if options['include_files']:
            for filename in options['include_files']:
                filename = os.path.abspath(filename)
                print(APACHE_INCLUDE_CONFIG % dict(filename=filename),
                        file=fp)

        if options['with_newrelic_platform']:
            print(APACHE_TOOLS_CONFIG % options, file=fp)

        if options['with_newrelic_platform']:
            print(APACHE_METRICS_CONFIG % options, file=fp)

_interval = 1.0
_times = {}
_files = []

_running = False
_queue = queue.Queue()
_lock = threading.Lock()

def _restart(path):
    _queue.put(True)
    prefix = 'monitor (pid=%d):' % os.getpid()
    print('%s Change detected to "%s".' % (prefix, path), file=sys.stderr)
    print('%s Triggering process restart.' % prefix, file=sys.stderr)
    os.kill(os.getpid(), signal.SIGINT)

def _modified(path):
    try:
        # If path doesn't denote a file and were previously
        # tracking it, then it has been removed or the file type
        # has changed so force a restart. If not previously
        # tracking the file then we can ignore it as probably
        # pseudo reference such as when file extracted from a
        # collection of modules contained in a zip file.

        if not os.path.isfile(path):
            return path in _times

        # Check for when file last modified.

        mtime = os.stat(path).st_mtime
        if path not in _times:
            _times[path] = mtime

        # Force restart when modification time has changed, even
        # if time now older, as that could indicate older file
        # has been restored.

        if mtime != _times[path]:
            return True
    except Exception:
        # If any exception occured, likely that file has been
        # been removed just before stat(), so force a restart.

        return True

    return False

def _monitor():
    global _files

    while True:
        # Check modification times on all files in sys.modules.

        for module in list(sys.modules.values()):
            if not hasattr(module, '__file__'):
                continue
            path = getattr(module, '__file__')
            if not path:
                continue
            if os.path.splitext(path)[1] in ['.pyc', '.pyo', '.pyd']:
                path = path[:-1]
            if _modified(path):
                return _restart(path)

        # Check modification times on files which have
        # specifically been registered for monitoring.

        for path in _files:
            if _modified(path):
                return _restart(path)

        # Go to sleep for specified interval.

        try:
            return _queue.get(timeout=_interval)

        except queue.Empty:
            pass

_thread = threading.Thread(target=_monitor)
_thread.setDaemon(True)

def _exiting():
    try:
        _queue.put(True)
    except Exception:
        pass
    _thread.join()

def track_changes(path):
    if not path in _files:
        _files.append(path)

def start_reloader(interval=1.0):
    global _interval
    if interval < _interval:
        _interval = interval

    global _running
    _lock.acquire()
    if not _running:
        prefix = 'monitor (pid=%d):' % os.getpid()
        print('%s Starting change monitor.' % prefix, file=sys.stderr)
        _running = True
        _thread.start()
        atexit.register(_exiting)
    _lock.release()

class PostMortemDebugger(object):

    def __init__(self, application, startup):
        self.application = application
        self.generator = None

        import pdb
        self.debugger = pdb.Pdb()

        if startup:
            self.activate_console()

    def activate_console(self):
        self.debugger.set_trace(sys._getframe().f_back)

    def run_post_mortem(self):
        self.debugger.reset()
        self.debugger.interaction(None, sys.exc_info()[2])

    def __call__(self, environ, start_response):
        try:
            self.generator = self.application(environ, start_response)
            return self
        except Exception:
            self.run_post_mortem()
            raise

    def __iter__(self):
        try:
            for item in self.generator:
                yield item
        except Exception:
            self.run_post_mortem()
            raise

    def close(self):
        try:
            if hasattr(self.generator, 'close'):
                return self.generator.close()
        except Exception:
            self.run_post_mortem()
            raise

class RequestRecorder(object):

    def __init__(self, application, savedir):
        self.application = application
        self.savedir = savedir
        self.lock = threading.Lock()
        self.pid = os.getpid()
        self.count = 0

    def __call__(self, environ, start_response):
        with self.lock:
            self.count += 1
            count = self.count

        key = "%s-%s-%s" % (int(time.time()*1000000), self.pid, count)

        iheaders = os.path.join(self.savedir, key + ".iheaders")
        iheaders_fp = open(iheaders, 'w')

        icontent = os.path.join(self.savedir, key + ".icontent")
        icontent_fp = open(icontent, 'w+b')

        oheaders = os.path.join(self.savedir, key + ".oheaders")
        oheaders_fp = open(oheaders, 'w')

        ocontent = os.path.join(self.savedir, key + ".ocontent")
        ocontent_fp = open(ocontent, 'w+b')

        oaexcept = os.path.join(self.savedir, key + ".oaexcept")
        oaexcept_fp = open(oaexcept, 'w')

        orexcept = os.path.join(self.savedir, key + ".orexcept")
        orexcept_fp = open(orexcept, 'w')

        ofexcept = os.path.join(self.savedir, key + ".ofexcept")
        ofexcept_fp = open(ofexcept, 'w')

        errors = environ['wsgi.errors']
        pprint.pprint(environ, stream=iheaders_fp)
        iheaders_fp.close()

        input = environ['wsgi.input']

        data = input.read(8192)

        while data:
            icontent_fp.write(data)
            data = input.read(8192)

        icontent_fp.flush()
        icontent_fp.seek(0, os.SEEK_SET)

        environ['wsgi.input'] = icontent_fp

        def _start_response(status, response_headers, *args):
            pprint.pprint(((status, response_headers)+args),
                    stream=oheaders_fp)

            _write = start_response(status, response_headers, *args)

            def write(self, data):
                ocontent_fp.write(data)
                ocontent_fp.flush()
                return _write(data)

            return write

        try:
            try:
                result = self.application(environ, _start_response)

            except:
                traceback.print_exception(*sys.exc_info(), file=oaexcept_fp)
                raise

            try:
                for data in result:
                    ocontent_fp.write(data)
                    ocontent_fp.flush()
                    yield data

            except:
                traceback.print_exception(*sys.exc_info(), file=orexcept_fp)
                raise

            finally:
                try:
                    if hasattr(result, 'close'):
                        result.close()

                except:
                    traceback.print_exception(*sys.exc_info(),
                            file=ofexcept_fp)
                    raise

        finally:
            oheaders_fp.close()
            ocontent_fp.close()
            oaexcept_fp.close()
            orexcept_fp.close()
            ofexcept_fp.close()

class ApplicationHandler(object):

    def __init__(self, entry_point, application_type='script',
            callable_object='application', mount_point='/',
            with_newrelic_agent=False, debug_mode=False,
            enable_debugger=False, debugger_startup=False,
            enable_recorder=False, recorder_directory=None):

        self.entry_point = entry_point
        self.application_type = application_type
        self.callable_object = callable_object
        self.mount_point = mount_point

        if application_type == 'module':
            __import__(entry_point)
            self.module = sys.modules[entry_point]
            self.application = getattr(self.module, callable_object)
            self.target = self.module.__file__
            parts = os.path.splitext(self.target)[-1]
            if parts[-1].lower() in ('.pyc', '.pyd', '.pyd'):
                self.target = parts[0] + '.py'

        elif application_type == 'paste':
            from paste.deploy import loadapp
            self.application = loadapp('config:%s' % entry_point)
            self.target = entry_point

        elif application_type != 'static':
            self.module = imp.new_module('__wsgi__')
            self.module.__file__ = entry_point

            with open(entry_point, 'r') as fp:
                code = compile(fp.read(), entry_point, 'exec',
                        dont_inherit=True)
                exec(code, self.module.__dict__)

            sys.modules['__wsgi__'] = self.module
            self.application = getattr(self.module, callable_object)
            self.target = entry_point

        try:
            self.mtime = os.path.getmtime(self.target)
        except Exception:
            self.mtime = None

        if with_newrelic_agent:
            self.setup_newrelic_agent()

        self.debug_mode = debug_mode
        self.enable_debugger = enable_debugger

        if enable_debugger:
            self.setup_debugger(debugger_startup)

        if enable_recorder:
            self.setup_recorder(recorder_directory)

    def setup_newrelic_agent(self):
        import newrelic.agent

        config_file = os.environ.get('NEW_RELIC_CONFIG_FILE')
        environment = os.environ.get('NEW_RELIC_ENVIRONMENT')

        global_settings = newrelic.agent.global_settings()
        if global_settings.log_file is None:
            global_settings.log_file = 'stderr'

        newrelic.agent.initialize(config_file, environment)
        newrelic.agent.register_application()

        self.application = newrelic.agent.WSGIApplicationWrapper(
                self.application)

    def setup_debugger(self, startup):
        self.application = PostMortemDebugger(self.application, startup)

    def setup_recorder(self, savedir):
        self.application = RequestRecorder(self.application, savedir)

    def reload_required(self, environ):
        if self.debug_mode:
            return False

        try:
            mtime = os.path.getmtime(self.target)
        except Exception:
            mtime = None

        return mtime != self.mtime

    def handle_request(self, environ, start_response):
        # Strip out the leading component due to internal redirect in
        # Apache when using web application as fallback resource.

        mount_point = environ.get('mod_wsgi.mount_point')

        script_name = environ.get('SCRIPT_NAME')
        path_info = environ.get('PATH_INFO')

        if mount_point is not None:
            # If this is set then it means that SCRIPT_NAME was
            # overridden by a trusted proxy header. In this case
            # we want to ignore any local mount point, simply
            # stripping it from the path.

            script_name = environ['mod_wsgi.script_name']

            environ['PATH_INFO'] = script_name + path_info

            if self.mount_point != '/':
                if environ['PATH_INFO'].startswith(self.mount_point):
                    environ['PATH_INFO'] = environ['PATH_INFO'][len(
                            self.mount_point):]

        else:
            environ['SCRIPT_NAME'] = ''
            environ['PATH_INFO'] = script_name + path_info

            if self.mount_point != '/':
                if environ['PATH_INFO'].startswith(self.mount_point):
                    environ['SCRIPT_NAME'] = self.mount_point
                    environ['PATH_INFO'] = environ['PATH_INFO'][len(
                            self.mount_point):]

        return self.application(environ, start_response)

    def __call__(self, environ, start_response):
        return self.handle_request(environ, start_response)

class ResourceHandler(object):

    def __init__(self, resources):
        self.resources = {}

        for extension, script in resources:
            extension_name = re.sub('[^\w]{1}', '_', extension)
            module_name = '__wsgi_resource%s__' % extension_name
            module = imp.new_module(module_name)
            module.__file__ = script

            with open(script, 'r') as fp:
                code = compile(fp.read(), script, 'exec',
                        dont_inherit=True)
                exec(code, module.__dict__)

            sys.modules[module_name] = module
            self.resources[extension] = module

    def resource_extension(self, resource):
        return os.path.splitext(resource)[-1]

    def reload_required(self, resource):
        extension = self.resource_extension(resource)
        function = getattr(self.resources[extension], 'reload_required', None)
        if function is not None:
            return function(environ)
        return False

    def handle_request(self, environ, start_response):
        resource = environ['SCRIPT_NAME']
        extension = self.resource_extension(resource)
        module = self.resources[extension]
        function = getattr(module, 'handle_request', None)
        if function is not None:
            return function(environ, start_response)
        function = getattr(module, 'application')
        return function(environ, start_response)

    def __call__(self, environ, start_response):
        return self.handle_request(environ, start_response)

WSGI_HANDLER_SCRIPT = """
import os
import sys
import atexit
import time

import mod_wsgi.server

working_directory = '%(working_directory)s'

entry_point = '%(entry_point)s'
application_type = '%(application_type)s'
callable_object = '%(callable_object)s'
mount_point = '%(mount_point)s'
with_newrelic_agent = %(with_newrelic_agent)s
newrelic_config_file = '%(newrelic_config_file)s'
newrelic_environment = '%(newrelic_environment)s'
reload_on_changes = %(reload_on_changes)s
debug_mode = %(debug_mode)s
enable_debugger = %(enable_debugger)s
debugger_startup = %(debugger_startup)s
enable_coverage = %(enable_coverage)s
coverage_directory = '%(coverage_directory)s'
enable_profiler = %(enable_profiler)s
profiler_directory = '%(profiler_directory)s'
enable_recorder = %(enable_recorder)s
recorder_directory = '%(recorder_directory)s'
enable_gdb = %(enable_gdb)s

os.environ['MOD_WSGI_EXPRESS'] = 'true'
os.environ['MOD_WSGI_SERVER_NAME'] = '%(server_host)s'
os.environ['MOD_WSGI_SERVER_ALIASES'] = %(server_aliases)r or ''

if reload_on_changes:
    os.environ['MOD_WSGI_RELOADER_ENABLED'] = 'true'

if debug_mode:
    os.environ['MOD_WSGI_DEBUG_MODE'] = 'true'

    # We need to fiddle sys.path as we are not using daemon mode and so
    # the working directory will not be added to sys.path by virtue of
    # 'home' option to WSGIDaemonProcess directive. We could use the
    # WSGIPythonPath directive, but that will cause .pth files to also
    # be evaluated.

    sys.path.insert(0, working_directory)

if enable_debugger:
    os.environ['MOD_WSGI_DEBUGGER_ENABLED'] = 'true'

def output_coverage_report():
    coverage_info.stop()
    coverage_info.html_report(directory=coverage_directory)

if enable_coverage:
    os.environ['MOD_WSGI_COVERAGE_ENABLED'] = 'true'

    from coverage import coverage
    coverage_info = coverage()
    coverage_info.start()
    atexit.register(output_coverage_report)

def output_profiler_data():
    profiler_info.disable()
    output_file = '%%s-%%d.pstats' %% (int(time.time()*1000000), os.getpid())
    output_file = os.path.join(profiler_directory, output_file)
    profiler_info.dump_stats(output_file)

if enable_profiler:
    os.environ['MOD_WSGI_PROFILER_ENABLED'] = 'true'

    from cProfile import Profile
    profiler_info = Profile()
    profiler_info.enable()
    atexit.register(output_profiler_data)

if enable_recorder:
    os.environ['MOD_WSGI_RECORDER_ENABLED'] = 'true'

if enable_gdb:
    os.environ['MOD_WSGI_GDB_ENABLED'] = 'true'

if with_newrelic_agent:
    if newrelic_config_file:
        os.environ['NEW_RELIC_CONFIG_FILE'] = newrelic_config_file
    if newrelic_environment:
        os.environ['NEW_RELIC_ENVIRONMENT'] = newrelic_environment

handler = mod_wsgi.server.ApplicationHandler(entry_point,
        application_type=application_type, callable_object=callable_object,
        mount_point=mount_point, with_newrelic_agent=with_newrelic_agent,
        debug_mode=debug_mode, enable_debugger=enable_debugger,
        debugger_startup=debugger_startup, enable_recorder=enable_recorder,
        recorder_directory=recorder_directory)

reload_required = handler.reload_required
handle_request = handler.handle_request

if reload_on_changes and not debug_mode:
    mod_wsgi.server.start_reloader()
"""

WSGI_RESOURCE_SCRIPT = """
import mod_wsgi.server

resources = %(resources)s

handler = mod_wsgi.server.ResourceHandler(resources)

reload_required = handler.reload_required
handle_request = handler.handle_request
"""

WSGI_DEFAULT_SCRIPT = """
CONTENT = b'''
<html>
<head>
<title>My web site runs on Malt Whiskey</title>
</head>
<body style="margin-top: 100px;">
<table align="center"; style="width: 850px;" border="0" cellpadding="30">
<tbody>
<tr>
<td>
<img style="width: 275px; height: 445px;"
  src="/__wsgi__/images/snake-whiskey.jpg">
</td>
<td style="text-align: center;">
<span style="font-family: Arial,Helvetica,sans-serif;
  font-weight: bold; font-size: 70px;">
My web site<br>runs on<br>Malt Whiskey<br>
<br>
</span>
<span style="font-family: Arial,Helvetica,sans-serif;
  font-weight: bold;">
For further information on configuring mod_wsgi,<br>
see the <a href="%(documentation_url)s">documentation</a>.
</span>
</td>
</tr>
</tbody>
</table>
</body>
</html>
'''

def application(environ, start_response):
    status = '200 OK'
    output = CONTENT

    response_headers = [('Content-type', 'text/html'),
                        ('Content-Length', str(len(output)))]
    start_response(status, response_headers)

    return [output]
"""

def generate_wsgi_handler_script(options):
    path = os.path.join(options['server_root'], 'handler.wsgi')
    with open(path, 'w') as fp:
        print(WSGI_HANDLER_SCRIPT % options, file=fp)

    path = os.path.join(options['server_root'], 'resource.wsgi')
    with open(path, 'w') as fp:
        print(WSGI_RESOURCE_SCRIPT % dict(resources=repr(
                options['handler_scripts'])), file=fp)

    path = os.path.join(options['server_root'], 'default.wsgi')
    with open(path, 'w') as fp:
        print(WSGI_DEFAULT_SCRIPT % options, file=fp)

SERVER_METRICS_SCRIPT = """
import os
import logging

newrelic_config_file = '%(newrelic_config_file)s'
newrelic_environment = '%(newrelic_environment)s'

with_newrelic_platform = %(with_newrelic_platform)s

if with_newrelic_platform:
    if newrelic_config_file:
        os.environ['NEW_RELIC_CONFIG_FILE'] = newrelic_config_file
    if newrelic_environment:
        os.environ['NEW_RELIC_ENVIRONMENT'] = newrelic_environment

logging.basicConfig(level=logging.INFO,
    format='%%(name)s (pid=%%(process)d, level=%%(levelname)s): %%(message)s')

_logger = logging.getLogger(__name__)

try:
    from mod_wsgi.metrics.newrelic import Agent

    agent = Agent()
    agent.start()

except ImportError:
    _logger.fatal('The module mod_wsgi.metrics.newrelic is not available. '
            'The New Relic platform plugin has been disabled. Install the '
            '"mod_wsgi-metrics" package.')
"""

def generate_server_metrics_script(options):
    path = os.path.join(options['server_root'], 'server-metrics.py')
    with open(path, 'w') as fp:
        print(SERVER_METRICS_SCRIPT % options, file=fp)

WSGI_CONTROL_SCRIPT = """
#!/bin/bash

# %(sys_argv)s

HTTPD="%(httpd_executable)s"
HTTPD_ARGS="%(httpd_arguments)s"

HTTPD_COMMAND="$HTTPD $HTTPD_ARGS"

MOD_WSGI_MODULES_DIRECTORY="%(modules_directory)s"
export MOD_WSGI_MODULES_DIRECTORY

SHLIBPATH="%(shlibpath)s"

if [ "x$SHLIBPATH" != "x" ]; then
    %(shlibpath_var)s="$SHLIBPATH:$%(shlibpath_var)s"
    export %(shlibpath_var)s
fi

MOD_WSGI_SERVER_ROOT="%(server_root)s"

export MOD_WSGI_SERVER_ROOT

MOD_WSGI_LISTENER_HOST="%(host)s"

export MOD_WSGI_LISTENER_HOST

MOD_WSGI_HTTP_PORT="%(port)s"
MOD_WSGI_HTTPS_PORT="%(https_port)s"

export MOD_WSGI_HTTP_PORT
export MOD_WSGI_HTTPS_PORT

WSGI_RUN_USER="${WSGI_RUN_USER:-%(user)s}"
WSGI_RUN_GROUP="${WSGI_RUN_GROUP:-%(group)s}"

MOD_WSGI_USER="${MOD_WSGI_USER:-${WSGI_RUN_USER}}"
MOD_WSGI_GROUP="${MOD_WSGI_GROUP:-${WSGI_RUN_GROUP}}"

export MOD_WSGI_USER
export MOD_WSGI_GROUP

if [ `id -u` = "0" -a ${MOD_WSGI_USER} = "root" ]; then
    cat << EOF

WARNING: When running as the 'root' user, it is required that the options
'--user' and '--group' be specified to mod_wsgi-express. These should
define a non 'root' user and group under which the Apache child worker
processes and mod_wsgi daemon processes should be run. Failure to specify
these options will result in Apache and/or the mod_wsgi daemon processes
failing to start. See the mod_wsgi-express documentation for further
information on this restriction.

EOF

fi

MOD_WSGI_WORKING_DIRECTORY="%(working_directory)s"

export MOD_WSGI_WORKING_DIRECTORY

LANG='%(lang)s'
LC_ALL='%(locale)s'

export LANG
export LC_ALL

ACMD="$1"
ARGV="$@"

if test -f %(server_root)s/envvars; then
    . %(server_root)s/envvars
fi

STATUSURL="http://%(host)s:%(port)s/server-status"

if [ "x$ARGV" = "x" ]; then
    ARGV="-h"
fi

GDB="%(gdb_executable)s"
ENABLE_GDB="%(enable_gdb)s"

PROCESS_NAME="%(process_name)s"

case $ACMD in
start|stop|restart|graceful|graceful-stop)
    if [ "x$ENABLE_GDB" != "xTrue" ]; then
        exec -a "$PROCESS_NAME" $HTTPD_COMMAND -k $ARGV
    else
        echo "run $HTTPD_ARGS -k $ARGV" > %(server_root)s/gdb.cmds
        gdb -x %(server_root)s/gdb.cmds $HTTPD
    fi
    ;;
configtest)
    exec $HTTPD_COMMAND -t
    ;;
status)
    exec %(python_executable)s -m webbrowser -t $STATUSURL
    ;;
*)
    exec $HTTPD_COMMAND $ARGV
esac
"""

APACHE_ENVVARS_FILE = """
. %(envvars_script)s
"""

def generate_control_scripts(options):
    path = os.path.join(options['server_root'], 'apachectl')
    with open(path, 'w') as fp:
        print(WSGI_CONTROL_SCRIPT.lstrip() % options, file=fp)

    os.chmod(path, 0o755)

    path = os.path.join(options['server_root'], 'envvars')

    if options['envvars_script']:
        with open(path, 'w') as fp:
            if options['envvars_script']:
                print(APACHE_ENVVARS_FILE.lstrip() % options, file=fp)

    elif not os.path.isfile(path):
        with open(path, 'w') as fp:
            pass

def check_percentage(option, opt_str, value, parser):
    if value is not None and value < 0 or value > 1:
        raise optparse.OptionValueError('%s option value needs to be within '
                'the range 0 to 1.' % opt_str)
    setattr(parser.values, option.dest, value)

option_list = (
    optparse.make_option('--application-type', default='script',
            metavar='TYPE', help='The type of WSGI application entry point '
            'that was provided. Defaults to \'script\', indicating the '
            'traditional mod_wsgi style WSGI script file specified by a '
            'filesystem path. Alternatively one can supply \'module\', '
            'indicating that the provided entry point is a Python module '
            'which should be imported using the standard Python import '
            'mechanism, or \'paste\' indicating that the provided entry '
            'point is a Paste deployment configuration file. If you want '
            'to just use the server to host static files only, then you '
            'can also instead supply \'static\' with the target being '
            'the directory containing the files to server or the current '
            'directory if none is supplied.'),

    optparse.make_option('--entry-point', default=None,
            metavar='FILE-PATH|MODULE', help='The file system path or '
            'module name identifying the file which contains the WSGI '
            'application entry point. How the value given is interpreted '
            'depends on the corresponding type identified using the '
            '\'--application-type\' option. Use of this option is the '
            'same as if the value had been given as argument but without '
            'any option specifier. A named option is also provided so '
            'as to make it clearer in a long option list what the entry '
            'point actually is. If both methods are used, that specified '
            'by this option will take precedence.'),

    optparse.make_option('--host', default=None, metavar='IP-ADDRESS',
            help='The specific host (IP address) interface on which '
            'requests are to be accepted. Defaults to listening on '
            'all host interfaces.'),
    optparse.make_option('--port', default=8000, type='int',
            metavar='NUMBER', help='The specific port to bind to and '
            'on which requests are to be accepted. Defaults to port 8000.'),

    optparse.make_option('--http2', action='store_true', default=False,
            help='Flag indicating whether HTTP/2 should be enabled.'
	    'Requires the mod_http2 module to be available.'),

    optparse.make_option('--https-port', type='int', metavar='NUMBER',
            help='The specific port to bind to and on which secure '
            'requests are to be accepted.'),
    optparse.make_option('--ssl-port', type='int', metavar='NUMBER',
            dest='https_port', help=optparse.SUPPRESS_HELP),

    optparse.make_option('--ssl-certificate-file', default=None,
            metavar='FILE-PATH', help='Specify the path to the SSL '
            'certificate file.'),
    optparse.make_option('--ssl-certificate-key-file', default=None,
            metavar='FILE-PATH', help='Specify the path to the private '
            'key file corresponding to the SSL certificate file.'),

    optparse.make_option('--ssl-certificate', default=None,
            metavar='FILE-PATH', help='Specify the common path to the SSL '
            'certificate files. This is a convenience function so that '
            'only one option is required to specify the location of the '
            'certificate file and the private key file. It is expected that '
            'the files have \'.crt\' and \'.key\' extensions. This option '
            'should refer to the common part of the names for both files '
            'which appears before the extension.'),

    optparse.make_option('--ssl-ca-certificate-file', default=None,
            metavar='FILE-PATH', help='Specify the path to the file with '
            'the CA certificates to be used for client authentication. When '
            'specified, access to the whole site will by default require '
            'client authentication. To require client authentication for '
            'only parts of the site, use the --ssl-verify-client option.'),

    optparse.make_option('--ssl-verify-client', action='append',
            metavar='URL-PATH', dest='ssl_verify_client_urls',
            help='Specify a sub URL of the site for which client '
            'authentication is required. When this option is specified, '
            'the default of client authentication being required for the '
            'whole site will be disabled and verification will only be '
            'required for the specified sub URL.'),

    optparse.make_option('--ssl-certificate-chain-file', default=None,
            metavar='FILE-PATH', help='Specify the path to a file '
            'containing the certificates of Certification Authorities (CA) '
            'which form the certificate chain of the server certificate.'),

    optparse.make_option('--ssl-environment', action='store_true',
            default=False, help='Flag indicating whether the standard set '
            'of SSL related variables are passed in the per request '
            'environment passed to a handler.'),

    optparse.make_option('--https-only', action='store_true',
            default=False, help='Flag indicating whether any requests '
	    'made using a HTTP request over the non secure connection '
            'should be redirected automatically to use a HTTPS request '
            'over the secure connection.'),

    optparse.make_option('--hsts-policy', default=None, metavar='PARAMS',
            help='Specify the HSTS policy that should be applied when '
            'HTTPS only connections are being enforced.'),

    optparse.make_option('--server-name', default=None, metavar='HOSTNAME',
            help='The primary host name of the web server. If this name '
            'starts with \'www.\' then an automatic redirection from the '
            'parent domain name to the \'www.\' server name will created.'),
    optparse.make_option('--server-alias', action='append',
            dest='server_aliases', metavar='HOSTNAME', help='A secondary '
            'host name for the web server. May include wildcard patterns.'),
    optparse.make_option('--allow-localhost', action='store_true',
            default=False, help='Flag indicating whether access via '
            'localhost should still be allowed when a server name has been '
            'specified and a name based virtual host has been configured.'),

    optparse.make_option('--processes', type='int', metavar='NUMBER',
            help='The number of worker processes (instances of the WSGI '
            'application) to be started up and which will handle requests '
            'concurrently. Defaults to a single process.'),
    optparse.make_option('--threads', type='int', default=5, metavar='NUMBER',
            help='The number of threads in the request thread pool of '
            'each process for handling requests. Defaults to 5 in each '
            'process.'),

    optparse.make_option('--max-clients', type='int', default=None,
            metavar='NUMBER', help='The maximum number of simultaneous '
            'client connections that will be accepted. This will default '
            'to being 1.5 times the total number of threads in the '
            'request thread pools across all process handling requests.'),

    optparse.make_option('--initial-workers', type='float', default=None,
            metavar='NUMBER', action='callback', callback=check_percentage,
            help='The initial number of workers to create on startup '
            'expressed as a percentage of the maximum number of clients. '
            'The value provided should be between 0 and 1. The default is '
            'dependent on the type of MPM being used.'),
    optparse.make_option('--minimum-spare-workers', type='float',
            default=None, metavar='NUMBER', action='callback',
            callback=check_percentage, help='The minimum number of spare '
            'workers to maintain expressed as a percentage of the maximum '
            'number of clients. The value provided should be between 0 and '
            '1. The default is dependent on the type of MPM being used.'),
    optparse.make_option('--maximum-spare-workers', type='float',
            default=None, metavar='NUMBER', action='callback',
            callback=check_percentage, help='The maximum number of spare '
            'workers to maintain expressed as a percentage of the maximum '
            'number of clients. The value provided should be between 0 and '
            '1. The default is dependent on the type of MPM being used.'),

    optparse.make_option('--limit-request-body', type='int', default=10485760,
            metavar='NUMBER', help='The maximum number of bytes which are '
            'allowed in a request body. Defaults to 10485760 (10MB).'),

    optparse.make_option('--maximum-requests', type='int', default=0,
            metavar='NUMBER', help='The number of requests after which '
            'any one worker process will be restarted and the WSGI '
            'application reloaded. Defaults to 0, indicating that the '
            'worker process should never be restarted based on the number '
            'of requests received.'),

    optparse.make_option('--startup-timeout', type='int', default=15,
            metavar='SECONDS', help='Maximum number of seconds allowed '
            'to pass waiting for the application to be successfully '
            'loaded and started by a worker process. When this timeout '
            'has been reached without the application having been '
            'successfully loaded and started, the worker process will '
            'be forced to restart. Defaults to 15 seconds.'),

    optparse.make_option('--shutdown-timeout', type='int', default=5,
            metavar='SECONDS', help='Maximum number of seconds allowed '
            'to pass when waiting for a worker process to shutdown as a '
            'result of the maximum number of requests or inactivity timeout '
            'being reached, or when a user initiated SIGINT signal is sent '
            'to a worker process. When this timeout has been reached the '
            'worker process will be forced to exit even if there are '
            'still active requests or it is still running Python exit '
            'functions. Defaults to 5 seconds.'),

    optparse.make_option('--restart-interval', type='int', default='0',
            metavar='SECONDS', help='Number of seconds between worker '
            'process restarts. If graceful timeout is also specified, '
            'active requests will be given a chance to complete before '
            'the process is forced to exit and restart. Not enabled by '
            'default.'),

    optparse.make_option('--graceful-timeout', type='int', default=15,
            metavar='SECONDS', help='Grace period for requests to complete '
            'normally, while still accepting new requests, when worker '
            'processes are being shutdown and restarted due to maximum '
            'requests being reached or restart interval having expired. '
            'Defaults to 15 seconds.'),
    optparse.make_option('--eviction-timeout', type='int', default=0,
            metavar='SECONDS', help='Grace period for requests to complete '
            'normally, while still accepting new requests, when the WSGI '
            'application is being evicted from the worker processes, and '
            'the process restarted, due to forced graceful restart signal. '
            'Defaults to timeout specified by \'--graceful-timeout\' '
            'option.'),

    optparse.make_option('--deadlock-timeout', type='int', default=60,
            metavar='SECONDS', help='Maximum number of seconds allowed '
            'to pass before the worker process is forcibly shutdown and '
            'restarted after a potential deadlock on the Python GIL has '
            'been detected. Defaults to 60 seconds.'),

    optparse.make_option('--inactivity-timeout', type='int', default=0,
            metavar='SECONDS', help='Maximum number of seconds allowed '
            'to pass before the worker process is shutdown and restarted '
            'when the worker process has entered an idle state and is no '
            'longer receiving new requests. Not enabled by default.'),
    optparse.make_option('--ignore-activity', action='append',
            dest='ignore_activity', metavar='URL-PATH', help='Specify '
            'the URL path for any location where activity should be '
            'ignored when the \'--activity-timeout\' option is used. '
            'This would be used on health check URLs so that health '
            'checks do not prevent process restarts due to inactivity.'),

    optparse.make_option('--request-timeout', type='int', default=60,
            metavar='SECONDS', help='Maximum number of seconds allowed '
            'to pass before the worker process is forcibly shutdown and '
            'restarted when a request does not complete in the expected '
            'time. In a multi threaded worker, the request time is '
            'calculated as an average across all request threads. Defaults '
            'to 60 seconds.'),

    optparse.make_option('--connect-timeout', type='int', default=15,
            metavar='SECONDS', help='Maximum number of seconds allowed '
            'to pass before giving up on attempting to get a connection '
            'to the worker process from the Apache child process which '
            'accepted the request. This comes into play when the worker '
            'listener backlog limit is exceeded. Defaults to 15 seconds.'),

    optparse.make_option('--socket-timeout', type='int', default=60,
            metavar='SECONDS', help='Maximum number of seconds allowed '
            'to pass before timing out on a read or write operation on '
            'a socket and aborting the request. Defaults to 60 seconds.'),

    optparse.make_option('--queue-timeout', type='int', default=45,
            metavar='SECONDS', help='Maximum number of seconds allowed '
            'for a request to be accepted by a worker process to be '
            'handled, taken from the time when the Apache child process '
            'originally accepted the request. Defaults to 30 seconds.'),

    optparse.make_option('--header-timeout', type='int', default=15,
            metavar='SECONDS', help='The number of seconds allowed for '
            'receiving the request including the headers. This may be '
            'dynamically increased if a minimum rate for reading the '
            'request and headers is also specified, up to any limit '
            'imposed by a maximum header timeout. Defaults to 15 seconds.'),

    optparse.make_option('--header-max-timeout', type='int', default=30,
            metavar='SECONDS', help='Maximum number of seconds allowed for '
            'receiving the request including the headers. This is the hard '
            'limit after taking into consideration and increases to the '
            'basic timeout due to minimum rate for reading the request and '
            'headers which may be specified. Defaults to 30 seconds.'),

    optparse.make_option('--header-min-rate', type='int', default=500,
            metavar='BYTES', help='The number of bytes required to be sent '
            'as part of the request and headers to trigger a dynamic '
            'increase in the timeout on receiving the request including '
            'headers. Each time this number of bytes is received the timeout '
            'will be increased by 1 second up to any maximum specified by '
            'the maximum header timeout. Defaults to 500 bytes.'),

    optparse.make_option('--body-timeout', type='int', default=15,
            metavar='SECONDS', help='The number of seconds allowed for '
            'receiving the request body. This may be dynamically increased '
            'if a minimum rate for reading the request body is also '
            'specified, up to any limit imposed by a maximum body timeout. '
            'Defaults to 15 seconds.'),

    optparse.make_option('--body-max-timeout', type='int', default=0,
            metavar='SECONDS', help='Maximum number of seconds allowed for '
            'receiving the request body. This is the hard limit after '
            'taking into consideration and increases to the basic timeout '
            'due to minimum rate for reading the request body which may be '
            'specified. Defaults to 0 indicating there is no maximum.'),

    optparse.make_option('--body-min-rate', type='int', default=500,
            metavar='BYTES', help='The number of bytes required to be sent '
            'as part of the request body to trigger a dynamic increase in '
            'the timeout on receiving the request body. Each time this '
            'number of bytes is received the timeout will be increased '
            'by 1 second up to any maximum specified by the maximum body '
            'timeout. Defaults to 500 bytes.'),

    optparse.make_option('--server-backlog', type='int', default=500,
            metavar='NUMBER', help='Depth of server socket listener '
            'backlog for Apache child processes. Defaults to 500.'),

    optparse.make_option('--daemon-backlog', type='int', default=100,
            metavar='NUMBER', help='Depth of server socket listener '
            'backlog for daemon processes. Defaults to 100.'),

    optparse.make_option('--send-buffer-size', type='int', default=0,
            metavar='NUMBER', help='Size of socket buffer for sending '
            'data to daemon processes. Defaults to 0, indicating '
            'the system default socket buffer size is used.'),
    optparse.make_option('--receive-buffer-size', type='int', default=0,
            metavar='NUMBER', help='Size of socket buffer for receiving '
            'data from daemon processes. Defaults to 0, indicating '
            'the system default socket buffer size is used.'),
    optparse.make_option('--header-buffer-size', type='int', default=0,
            metavar='NUMBER', help='Size of buffer used for reading '
            'response headers from daemon processes. Defaults to 0, '
            'indicating internal default of 32768 bytes is used.'),
    optparse.make_option('--response-buffer-size', type='int', default=0,
            metavar='NUMBER', help='Maximum amount of response content '
            'that will be allowed to be buffered in the Apache child '
            'worker process when proxying the response from a daemon '
            'process. Defaults to 0, indicating internal default of '
            '65536 bytes is used.'),

    optparse.make_option('--reload-on-changes', action='store_true',
            default=False, help='Flag indicating whether worker processes '
            'should be automatically restarted when any Python code file '
            'loaded by the WSGI application has been modified. Defaults to '
            'being disabled. When reloading on any code changes is disabled, '
            'the worker processes will still though be reloaded if the '
            'WSGI script file itself is modified.'),

    optparse.make_option('--user', default=default_run_user(),
            metavar='USERNAME', help='When being run by the root user, '
            'the user that the WSGI application should be run as.'),
    optparse.make_option('--group', default=default_run_group(),
            metavar='GROUP', help='When being run by the root user, the '
            'group that the WSGI application should be run as.'),

    optparse.make_option('--callable-object', default='application',
            metavar='NAME', help='The name of the entry point for the WSGI '
            'application within the WSGI script file. Defaults to '
            'the name \'application\'.'),

    optparse.make_option('--map-head-to-get', default='Auto',
            metavar='OFF|ON|AUTO', help='Flag indicating whether HEAD '
            'requests should be mapped to a GET request. By default a HEAD '
            'request will be automatically mapped to a GET request when an '
            'Apache output filter is detected that may want to see the '
            'entire response in order to set up response headers correctly '
            'for a HEAD request. This can be disable by setting to \'Off\'.'),

    optparse.make_option('--document-root', metavar='DIRECTORY-PATH',
            help='The directory which should be used as the document root '
            'and which contains any static files.'),
    optparse.make_option('--directory-index', metavar='FILE-NAME',
            help='The name of a directory index resource to be found in the '
            'document root directory. Requests mapping to the directory '
            'will be mapped to this resource rather than being passed '
            'through to the WSGI application.'),
    optparse.make_option('--directory-listing', action='store_true',
            default=False, help='Flag indicating if directory listing '
            'should be enabled where static file application type is '
            'being used and no directory index file has been specified.'),

    optparse.make_option('--mount-point', metavar='URL-PATH', default='/',
            help='The URL path at which the WSGI application will be '
            'mounted. Defaults to being mounted at the root URL of the '
            'site.'),

    optparse.make_option('--url-alias', action='append', nargs=2,
            dest='url_aliases', metavar='URL-PATH FILE-PATH|DIRECTORY-PATH',
            help='Map a single static file or a directory of static files '
            'to a sub URL.'),
    optparse.make_option('--error-document', action='append', nargs=2,
            dest='error_documents', metavar='STATUS URL-PATH', help='Map '
            'a specific sub URL as the handler for HTTP errors generated '
            'by the web server.'),
    optparse.make_option('--error-override', action='store_true',
            default=False, help='Flag indicating whether Apache error '
            'documents will override application error responses.'),

    optparse.make_option('--proxy-mount-point', action='append', nargs=2,
            dest='proxy_mount_points', metavar='URL-PATH URL',
            help='Map a sub URL such that any requests against it will be '
            'proxied to the specified URL. This is only for proxying to a '
            'site as a whole, or a sub site, not individual resources.'),
    optparse.make_option('--proxy-url-alias', action='append', nargs=2,
            dest='proxy_mount_points', metavar='URL-PATH URL',
            help=optparse.SUPPRESS_HELP),

    optparse.make_option('--proxy-virtual-host', action='append', nargs=2,
            dest='proxy_virtual_hosts', metavar='HOSTNAME URL',
            help='Proxy any requests for the specified host name to the '
            'remote URL.'),

    optparse.make_option('--trust-proxy-header', action='append', default=[],
            dest='trusted_proxy_headers', metavar='HEADER-NAME',
            help='The name of any trusted HTTP header providing details '
            'of the front end client request when proxying.'),
    optparse.make_option('--trust-proxy', action='append', default=[],
            dest='trusted_proxies', metavar='IP-ADDRESS/SUBNET',
            help='The IP address or subnet corresponding to any trusted '
            'proxy.'),

    optparse.make_option('--keep-alive-timeout', type='int', default=0,
            metavar='SECONDS', help='The number of seconds which a client '
            'connection will be kept alive to allow subsequent requests '
            'to be made over the same connection. Defaults to 0, indicating '
            'that keep alive connections are disabled.'),

    optparse.make_option('--compress-responses', action='store_true',
            default=False, help='Flag indicating whether responses for '
            'common text based responses, such as plain text, HTML, XML, '
            'CSS and Javascript should be compressed.'),

    optparse.make_option('--server-metrics', action='store_true',
            default=False, help='Flag indicating whether internal server '
            'metrics will be available within the WSGI application. '
            'Defaults to being disabled.'),
    optparse.make_option('--server-status', action='store_true',
            default=False, help='Flag indicating whether web server status '
            'will be available at the /server-status sub URL. Defaults to '
            'being disabled.'),

    optparse.make_option('--host-access-script', metavar='SCRIPT-PATH',
            default=None, help='Specify a Python script file for '
            'performing host access checks.'),
    optparse.make_option('--auth-user-script', metavar='SCRIPT-PATH',
            default=None, help='Specify a Python script file for '
            'performing user authentication.'),
    optparse.make_option('--auth-type', metavar='TYPE',
            default='Basic', help='Specify the type of authentication '
            'scheme used when authenticating users. Defaults to using '
            '\'Basic\'. Alternate schemes available are \'Digest\'.'),

    optparse.make_option('--auth-group-script', metavar='SCRIPT-PATH',
            default=None, help='Specify a Python script file for '
            'performing group based authorization in conjunction with '
            'a user authentication script.'),
    optparse.make_option('--auth-group', metavar='NAME',
            default='wsgi', help='Specify the group which users should '
            'be a member of when using a group based authorization script. '
            'Defaults to \'wsgi\' as a place holder but should be '
            'overridden to be the actual group you use rather than '
            'making your group name match the default.'),

    optparse.make_option('--include-file', action='append',
            dest='include_files', metavar='FILE-PATH', help='Specify the '
            'path to an additional web server configuration file to be '
            'included at the end of the generated web server configuration '
            'file.'),

    optparse.make_option('--rewrite-rules', metavar='FILE-PATH',
            help='Specify an alternate server configuration file which '
            'contains rewrite rules. Defaults to using the '
            '\'rewrite.conf\' stored under the server root directory.'),

    optparse.make_option('--envvars-script', metavar='FILE-PATH',
            help='Specify an alternate script file for user defined web '
            'server environment variables. Defaults to using the '
            '\'envvars\' stored under the server root directory.'),

    optparse.make_option('--lang', default=None, metavar='NAME',
            help=optparse.SUPPRESS_HELP),
    optparse.make_option('--locale', default=None, metavar='NAME',
            help='Specify the natural language locale for the process '
            'as normally defined by the \'LC_ALL\' environment variable. '
            'If not specified, then the default locale for this process '
            'will be used. If the default locale is however \'C\' or '
            '\'POSIX\' then an attempt will be made to use either the '
            '\'en_US.UTF-8\' or \'C.UTF-8\' locales and if that is not '
            'possible only then fallback to the default locale of this '
            'process.'),

    optparse.make_option('--setenv', action='append', nargs=2,
            dest='setenv_variables', metavar='KEY VALUE', help='Specify '
            'a name/value pairs to be added to the per request WSGI environ '
            'dictionary'),
    optparse.make_option('--passenv', action='append',
            dest='passenv_variables', metavar='KEY', help='Specify the '
            'names of any process level environment variables which should '
            'be passed as a name/value pair in the per request WSGI '
            'environ dictionary.'),

    optparse.make_option('--working-directory', metavar='DIRECTORY-PATH',
            help='Specify the directory which should be used as the '
            'current working directory of the WSGI application. This '
            'directory will be searched when importing Python modules '
            'so long as the WSGI application doesn\'t subsequently '
            'change the current working directory. Defaults to the '
            'directory this script is run from.'),

    optparse.make_option('--pid-file', metavar='FILE-PATH',
            help='Specify an alternate file to be used to store the '
            'process ID for the root process of the web server.'),

    optparse.make_option('--server-root', metavar='DIRECTORY-PATH',
            help='Specify an alternate directory for where the generated '
            'web server configuration, startup files and logs will be '
            'stored. Defaults to a sub directory of /tmp.'),

    optparse.make_option('--server-mpm', action='append',
            dest='server_mpm_variables', metavar='NAME', help='Specify '
            'preferred MPM to use when using Apache 2.4 with dynamically '
            'loadable MPMs and more than one is available. By default '
            'the MPM precedence order when no preference is given is '
            '\"event\", \"worker" and \"prefork\".'),

    optparse.make_option('--log-directory', metavar='DIRECTORY-PATH',
            help='Specify an alternate directory for where the log files '
            'will be stored. Defaults to the server root directory.'),
    optparse.make_option('--log-level', default='warn', metavar='NAME',
            help='Specify the log level for logging. Defaults to \'warn\'.'),
    optparse.make_option('--access-log', action='store_true', default=False,
            help='Flag indicating whether the web server access log '
            'should be enabled. Defaults to being disabled.'),
    optparse.make_option('--startup-log', action='store_true', default=False,
            help='Flag indicating whether the web server startup log should '
            'be enabled. Defaults to being disabled.'),

    optparse.make_option('--verbose-debugging', action='store_true',
            dest='verbose_debugging', help=optparse.SUPPRESS_HELP),

    optparse.make_option('--log-to-terminal', action='store_true',
            default=False, help='Flag indicating whether logs should '
            'be directed back to the terminal. Defaults to being disabled. '
            'If --log-directory is set explicitly, it will override this '
            'option. If logging to the terminal is carried out, any '
            'rotating of log files will be disabled.'),

    optparse.make_option('--access-log-format', metavar='FORMAT',
            help='Specify the format of the access log records.'),
    optparse.make_option('--error-log-format', metavar='FORMAT',
            help='Specify the format of the error log records.'),

    optparse.make_option('--error-log-name', metavar='FILE-NAME',
            default='error_log', help='Specify the name of the error '
            'log file when it is being written to the log directory.'),
    optparse.make_option('--access-log-name', metavar='FILE-NAME',
            default='access_log', help='Specify the name of the access '
            'log file when it is being written to the log directory.'),
    optparse.make_option('--startup-log-name', metavar='FILE-NAME',
            default='startup_log', help='Specify the name of the startup '
            'log file when it is being written to the log directory.'),

    optparse.make_option('--rotate-logs', action='store_true', default=False,
            help='Flag indicating whether log rotation should be performed.'),
    optparse.make_option('--max-log-size', default=5, type='int',
            metavar='MB', help='The maximum size in MB the log file should '
            'be allowed to reach before log file rotation is performed.'),

    optparse.make_option('--rotatelogs-executable',
            default=apxs_config.ROTATELOGS, metavar='FILE-PATH',
            help='Override the path to the rotatelogs executable.'),

    optparse.make_option('--python-path', action='append',
            dest='python_paths', metavar='DIRECTORY-PATH', help='Specify '
            'the path to any additional directory that should be added to '
            'the Python module search path. Note that these directories will '
            'not be processed for \'.pth\' files. If processing of \'.pth\' '
            'files is required, set the \'PYTHONPATH\' environment variable '
            'in a script specified by the \'--envvars-script\' option.'),

    optparse.make_option('--python-eggs', metavar='DIRECTORY-PATH',
            help='Specify an alternate directory which should be used for '
            'unpacking of Python eggs. Defaults to a sub directory of '
            'the server root directory.'),

    optparse.make_option('--httpd-executable', default=apxs_config.HTTPD,
            metavar='FILE-PATH', help='Override the path to the Apache web '
            'server executable.'),
    optparse.make_option('--process-name', metavar='NAME', help='Override '
            'the name given to the Apache parent process. This might be '
            'needed when a process manager expects the process to be named '
            'a certain way but due to a sequence of exec calls the name '
            'changed.'),

    optparse.make_option('--modules-directory', default=apxs_config.LIBEXECDIR,
            metavar='DIRECTORY-PATH', help='Override the path to the Apache '
            'web server modules directory.'),
    optparse.make_option('--mime-types', default=find_mimetypes(),
            metavar='FILE-PATH', help='Override the path to the mime types '
            'file used by the web server.'),

    optparse.make_option('--add-handler', action='append', nargs=2,
            dest='handler_scripts', metavar='EXTENSION SCRIPT-PATH',
            help='Specify a WSGI application to be used as a special '
            'handler for any resources matched from the document root '
            'directory with a specific extension type.'),

    optparse.make_option('--chunked-request', action='store_true',
            default=False, help='Flag indicating whether requests which '
            'use chunked transfer encoding will be accepted.'),

    optparse.make_option('--with-newrelic', action='store_true',
            default=False, help='Flag indicating whether all New Relic '
            'performance monitoring features should be enabled.'),

    optparse.make_option('--with-newrelic-agent', action='store_true',
            default=False, help='Flag indicating whether the New Relic '
            'Python agent should be enabled for reporting application server '
            'metrics.'),
    optparse.make_option('--with-newrelic-platform', action='store_true',
            default=False, help='Flag indicating whether the New Relic '
            'platform plugin should be enabled for reporting server level '
            'metrics.'),

    optparse.make_option('--newrelic-config-file', metavar='FILE-PATH',
            default='', help='Specify the location of the New Relic agent '
            'configuration file.'),
    optparse.make_option('--newrelic-environment', metavar='NAME',
            default='', help='Specify the name of the environment section '
            'that should be used from New Relic agent configuration file.'),

    optparse.make_option('--with-php5', action='store_true', default=False,
            help='Flag indicating whether PHP 5 support should be enabled. '
            'PHP code files must use the \'.php\' extension.'),

    optparse.make_option('--with-cgi', action='store_true', default=False,
            help='Flag indicating whether CGI script support should be '
            'enabled. CGI scripts must use the \'.cgi\' extension and be '
            'executable'),

    optparse.make_option('--service-script', action='append', nargs=2,
            dest='service_scripts', metavar='SERVICE SCRIPT-PATH',
            help='Specify the name of a Python script to be loaded and '
            'executed in the context of a distinct daemon process. Used '
            'for running a managed service.'),
    optparse.make_option('--service-user', action='append', nargs=2,
            dest='service_users', metavar='SERVICE USERNAME',
            help='When being run by the root user, the user that the '
            'distinct daemon process started to run the managed service '
            'should be run as.'),
    optparse.make_option('--service-group', action='append', nargs=2,
            dest='service_groups', metavar='SERVICE GROUP',
            help='When being run by the root user, the group that the '
            'distinct daemon process started to run the managed service '
            'should be run as.'),
    optparse.make_option('--service-log-file', action='append', nargs=2,
            dest='service_log_files', metavar='SERVICE FILE-NAME',
            help='Specify the name of a separate log file to be used for '
            'the managed service.'),

    optparse.make_option('--enable-docs', action='store_true', default=False,
            help='Flag indicating whether the mod_wsgi documentation should '
            'be made available at the /__wsgi__/docs sub URL.'),

    optparse.make_option('--debug-mode', action='store_true', default=False,
            help='Flag indicating whether to run in single process mode '
            'to allow the running of an interactive Python debugger. This '
            'will override all options related to processes, threads and '
            'communication with workers. All forms of source code reloading '
            'will also be disabled. Both stdin and stdout will be attached '
            'to the console to allow interaction with the Python debugger.'),

    optparse.make_option('--enable-debugger', action='store_true',
            default=False, help='Flag indicating whether post mortem '
            'debugging of any exceptions which propagate out from the '
            'WSGI application when running in debug mode should be '
            'performed. Post mortem debugging is performed using the '
            'Python debugger (pdb).'),
    optparse.make_option('--debugger-startup', action='store_true',
            default=False, help='Flag indicating whether when post '
            'mortem debugging is enabled, that the debugger should '
            'also be thrown into the interactive console on initial '
            'startup of the server to allow breakpoints to be setup.'),

    optparse.make_option('--enable-coverage', action='store_true',
            default=False, help='Flag indicating whether coverage analysis '
            'is enabled when running in debug mode.'),
    optparse.make_option('--coverage-directory', metavar='DIRECTORY-PATH',
            default='', help='Override the path to the directory into '
            'which coverage analysis will be generated when enabled under '
            'debug mode.'),

    optparse.make_option('--enable-profiler', action='store_true',
            default=False, help='Flag indicating whether code profiling '
            'is enabled when running in debug mode.'),
    optparse.make_option('--profiler-directory', metavar='DIRECTORY-PATH',
            default='', help='Override the path to the directory into '
            'which profiler data will be written when enabled under debug '
            'mode.'),

    optparse.make_option('--enable-recorder', action='store_true',
            default=False, help='Flag indicating whether recording of '
            'requests is enabled when running in debug mode.'),
    optparse.make_option('--recorder-directory', metavar='DIRECTORY-PATH',
            default='', help='Override the path to the directory into '
            'which recorder data will be written when enabled under debug '
            'mode.'),

    optparse.make_option('--enable-gdb', action='store_true',
            default=False, help='Flag indicating whether Apache should '
            'be run under \'gdb\' when running in debug mode. This '
            'would be use to debug process crashes.'),
    optparse.make_option('--gdb-executable', default='gdb',
            metavar='FILE-PATH', help='Override the path to the gdb '
            'executable.'),

    optparse.make_option('--setup-only', action='store_true', default=False,
            help='Flag indicating that after the configuration files have '
            'been setup, that the command should then exit and not go on '
            'to actually run up the Apache server. This is to allow for '
            'the generation of the configuration with Apache then later '
            'being started separately using the generated \'apachectl\' '
            'script.'),
)

def cmd_setup_server(params):
    formatter = optparse.IndentedHelpFormatter()
    formatter.set_long_opt_delimiter(' ')

    usage = '%prog setup-server script [options]'
    parser = optparse.OptionParser(usage=usage, option_list=option_list,
            formatter=formatter)

    (options, args) = parser.parse_args(params)

    _cmd_setup_server('setup-server', args, vars(options))

def _mpm_module_defines(modules_directory, preferred=None):
    result = []
    workers = ['event', 'worker', 'prefork']
    found = False
    for name in workers:
        if not preferred or name in preferred:
            if os.path.exists(os.path.join(modules_directory,
                    'mod_mpm_%s.so' % name)):
                if not found:
                    result.append('-DMOD_WSGI_MPM_ENABLE_%s_MODULE' % name.upper())
                    found = True
                result.append('-DMOD_WSGI_MPM_EXISTS_%s_MODULE' % name.upper())
    return result

def _cmd_setup_server(command, args, options):
    options['sys_argv'] = repr(sys.argv)

    options['mod_wsgi_so'] = where()

    options['working_directory'] = options['working_directory'] or os.getcwd()
    options['working_directory'] = os.path.abspath(options['working_directory'])

    if not options['host']:
        options['listener_host'] = None
        options['host'] = 'localhost'
    else:
        options['listener_host'] = options['host']

    options['daemon_name'] = '(wsgi:%s:%s:%s)' % (options['host'],
            options['port'], os.getuid())

    if not options['server_root']:
        options['server_root'] = '/tmp/mod_wsgi-%s:%s:%s' % (options['host'],
                options['port'], os.getuid())

    try:
        os.mkdir(options['server_root'])
    except Exception:
        pass

    if options['ssl_certificate_file']:
        options['ssl_certificate_file'] = os.path.abspath(
                options['ssl_certificate_file'])

    if options['ssl_certificate_key_file']:
        options['ssl_certificate_key_file'] = os.path.abspath(
                options['ssl_certificate_key_file'])

    if options['ssl_certificate']:
        options['ssl_certificate'] = os.path.abspath(
                options['ssl_certificate'])

        options['ssl_certificate_file'] = options['ssl_certificate']
        options['ssl_certificate_file'] += '.crt'

        options['ssl_certificate_key_file'] = options['ssl_certificate']
        options['ssl_certificate_key_file'] += '.key'

    if options['ssl_ca_certificate_file']:
        options['ssl_ca_certificate_file'] = os.path.abspath(
                options['ssl_ca_certificate_file'])

    if options['ssl_certificate_chain_file']:
        options['ssl_certificate_chain_file'] = os.path.abspath(
                options['ssl_certificate_chain_file'])

    if options['entry_point']:
        args = [options['entry_point']]

    if not args:
        if options['application_type'] != 'static':
            options['entry_point'] = os.path.join(
                    options['server_root'], 'default.wsgi')
            options['application_type'] = 'script'
            options['enable_docs'] = True
        else:
            if not options['document_root']:
                options['document_root'] = os.getcwd()
            options['entry_point'] = '(static)'
    else:
        if options['application_type'] in ('script', 'paste'):
            options['entry_point'] = os.path.abspath(args[0])
        elif options['application_type'] == 'static':
            if not options['document_root']:
                options['document_root'] = os.path.abspath(args[0])
                options['entry_point'] = 'ignored'
            else:
                options['entry_point'] = 'overridden'
        else:
            options['entry_point'] = args[0]

    if options['host_access_script']:
        options['host_access_script'] = os.path.abspath(
                options['host_access_script'])

    if options['auth_user_script']:
        options['auth_user_script'] = os.path.abspath(
                options['auth_user_script'])

    if options['auth_group_script']:
        options['auth_group_script'] = os.path.abspath(
                options['auth_group_script'])

    options['documentation_directory'] = os.path.join(os.path.dirname(
            os.path.dirname(__file__)), 'docs')
    options['images_directory'] = os.path.join(os.path.dirname(
            os.path.dirname(__file__)), 'images')

    if os.path.exists(os.path.join(options['documentation_directory'],
            'index.html')):
        options['documentation_url'] = '/__wsgi__/docs/'
    else:
        options['documentation_url'] = 'http://www.modwsgi.org/'

    if not os.path.isabs(options['server_root']):
        options['server_root'] = os.path.abspath(options['server_root'])

    if not options['document_root']:
        options['document_root'] = os.path.join(options['server_root'],
                'htdocs')

    try:
        os.mkdir(options['document_root'])
    except Exception:
        pass

    if not options['mount_point'].startswith('/'):
        options['mount_point'] = os.path.normpath('/' + options['mount_point'])

    # Create subdirectories for mount points in document directory
    # so that fallback resource rewrite rule will work.

    if options['mount_point'] != '/':
        parts = options['mount_point'].rstrip('/').split('/')[1:]
        subdir = options['document_root']
        try:
            for part in parts:
                subdir = os.path.join(subdir, part)
                if not os.path.exists(subdir):
                    os.mkdir(subdir)
        except Exception:
            raise

    if not os.path.isabs(options['document_root']):
        options['document_root'] = os.path.abspath(options['document_root'])

    if not options['log_directory']:
        options['log_directory'] = options['server_root']
    else:
        # The --log-directory option overrides --log-to-terminal.
        options['log_to_terminal'] = False

    if options['log_to_terminal']:
        # The --log-to-terminal option overrides --rotate-logs.
        options['rotate_logs'] = False

    try:
        os.mkdir(options['log_directory'])
    except Exception:
        pass

    if not os.path.isabs(options['log_directory']):
        options['log_directory'] = os.path.abspath(options['log_directory'])

    if not options['log_to_terminal']:
        options['error_log_file'] = os.path.join(options['log_directory'],
                options['error_log_name'])
    else:
        try:
            with open('/dev/stderr', 'w'):
                pass
        except IOError:
            options['error_log_file'] = '|%s' % find_program(
                    ['tee'], default='tee')
        else:
            options['error_log_file'] = '/dev/stderr'

    if not options['log_to_terminal']:
        options['access_log_file'] = os.path.join(
                options['log_directory'], options['access_log_name'])
    else:
        try:
            with open('/dev/stdout', 'w'):
                pass
        except IOError:
            options['access_log_file'] = '|%s' % find_program(
                    ['tee'], default='tee')
        else:
            options['access_log_file'] = '/dev/stdout'

    if options['access_log_format']:
        if options['access_log_format'] in ('common', 'combined'):
            options['log_format_nickname'] = options['access_log_format']
            options['access_log_format'] = 'undefined'
        else:
            options['log_format_nickname'] = 'custom'
    else:
        options['log_format_nickname'] = 'common'
        options['access_log_format'] = 'undefined'

    options['access_log_format'] = options['access_log_format'].replace(
            '\"', '\\"')

    if options['error_log_format']:
        options['error_log_format'] = options['error_log_format'].replace(
                '\"', '\\"')

    options['pid_file'] = ((options['pid_file'] and os.path.abspath(
            options['pid_file'])) or os.path.join(options['server_root'],
            'httpd.pid'))

    options['python_eggs'] = (os.path.abspath(options['python_eggs']) if
            options['python_eggs'] is not None else None)

    if options['python_eggs'] is None:
        options['python_eggs'] = os.path.join(options['server_root'],
                'python-eggs')

    try:
        os.mkdir(options['python_eggs'])
        if os.getuid() == 0:
            import pwd
            import grp
            os.chown(options['python_eggs'],
                    pwd.getpwnam(options['user']).pw_uid,
                    grp.getgrnam(options['group']).gr_gid)
    except Exception:
        pass

    if options['python_paths'] is None:
        options['python_paths'] = []

    options['python_path'] = ':'.join(options['python_paths'])

    options['multiprocess'] = options['processes'] is not None
    options['processes'] = options['processes'] or 1

    options['python_home'] = sys.prefix

    options['keep_alive'] = options['keep_alive_timeout'] != 0

    request_read_timeout = ''

    if options['header_timeout'] > 0:
        request_read_timeout += 'header=%d' % options['header_timeout']
        if options['header_max_timeout'] > 0:
            request_read_timeout += '-%d' % options['header_max_timeout']
        if options['header_min_rate'] > 0:
            request_read_timeout += ',MinRate=%d' % options['header_min_rate']
        
    if options['body_timeout'] > 0:
        request_read_timeout += ' body=%d' % options['body_timeout']
        if options['body_max_timeout'] > 0:
            request_read_timeout += '-%d' % options['body_max_timeout']
        if options['body_min_rate'] > 0:
            request_read_timeout += ',MinRate=%d' % options['body_min_rate']

    options['request_read_timeout'] = request_read_timeout

    if options['server_metrics']:
        options['server_metrics_flag'] = 'On'
    else:
        options['server_metrics_flag'] = 'Off'

    if options['handler_scripts']:
        handler_scripts = []
        for extension, script in options['handler_scripts']:
            if not os.path.isabs(script):
                script = os.path.abspath(script)
            handler_scripts.append((extension, script))
        options['handler_scripts'] = handler_scripts

    if options['newrelic_config_file']:
        options['newrelic_config_file'] = os.path.abspath(
                options['newrelic_config_file'])

    if options['with_newrelic']:
        options['with_newrelic_agent'] = True
        options['with_newrelic_platform'] = True

    if options['with_newrelic_platform']:
        options['server_metrics'] = True

    if options['service_scripts']:
        service_scripts = []
        for name, script in options['service_scripts']:
            if not os.path.isabs(script):
                script = os.path.abspath(script)
            service_scripts.append((name, script))
        options['service_scripts'] = service_scripts

    max_clients = options['processes'] * options['threads']

    if options['max_clients'] is not None:
        max_clients = max(options['max_clients'], max_clients)
    else:
        max_clients = 10 + max(10, int(1.5 * max_clients))

    initial_workers = options['initial_workers']
    min_spare_workers = options['minimum_spare_workers']
    max_spare_workers = options['maximum_spare_workers']

    if initial_workers is None:
        prefork_initial_workers = 0.05
    else:
        prefork_initial_workers = initial_workers

    if min_spare_workers is None:
        prefork_min_spare_workers = prefork_initial_workers
    else:
        prefork_min_spare_workers = min_spare_workers

    if max_spare_workers is None:
        prefork_max_spare_workers = 0.1
    else:
        prefork_max_spare_workers = max_spare_workers

    options['prefork_max_clients'] = max_clients
    options['prefork_server_limit'] = max_clients
    options['prefork_start_servers'] = max(1, int(
            prefork_initial_workers * max_clients))
    options['prefork_min_spare_servers'] = max(1, int(
            prefork_min_spare_workers * max_clients))
    options['prefork_max_spare_servers'] = max(1, int(
            prefork_max_spare_workers * max_clients))

    if initial_workers is None:
        worker_initial_workers = 0.2
    else:
        worker_initial_workers = initial_workers

    if min_spare_workers is None:
        worker_min_spare_workers = worker_initial_workers
    else:
        worker_min_spare_workers = min_spare_workers

    if max_spare_workers is None:
        worker_max_spare_workers = 0.6
    else:
        worker_max_spare_workers = max_spare_workers

    options['worker_max_clients'] = max_clients

    if max_clients > 20:
        options['worker_threads_per_child'] = int(max_clients /
                (int(max_clients / 20) + 1))
    else:
        options['worker_threads_per_child'] = 10

    options['worker_thread_limit'] = options['worker_threads_per_child']

    count = max_clients / options['worker_threads_per_child']
    options['worker_server_limit'] = int(math.floor(count))
    if options['worker_server_limit'] != count:
        options['worker_server_limit'] += 1

    options['worker_max_clients'] = (options['worker_server_limit'] *
            options['worker_threads_per_child'])

    options['worker_start_servers'] = max(1,
            int(worker_initial_workers * options['worker_server_limit']))
    options['worker_min_spare_threads'] = max(
            options['worker_threads_per_child'],
            int(worker_min_spare_workers * options['worker_server_limit']) *
            options['worker_threads_per_child'])
    options['worker_max_spare_threads'] = max(
            options['worker_threads_per_child'],
            int(worker_max_spare_workers * options['worker_server_limit']) *
            options['worker_threads_per_child'])

    options['httpd_conf'] = os.path.join(options['server_root'], 'httpd.conf')

    options['httpd_executable'] = os.environ.get('HTTPD',
            options['httpd_executable'])

    if not os.path.isabs(options['httpd_executable']):
         options['httpd_executable'] = find_program(
                 [options['httpd_executable']], 'httpd', ['/usr/sbin'])

    if not options['process_name']:
        options['process_name'] = os.path.basename(
                options['httpd_executable']) + ' (mod_wsgi-express)'

    options['process_name'] = options['process_name'].ljust(
            len(options['daemon_name']))

    options['rewrite_rules'] = (os.path.abspath(
            options['rewrite_rules']) if options['rewrite_rules'] is
            not None else None)

    options['envvars_script'] = (os.path.abspath(
            options['envvars_script']) if options['envvars_script'] is
            not None else None)

    if options['locale'] is None:
        options['locale'] = options['lang']

    if options['locale'] is None:
        language, encoding = locale.getdefaultlocale()
        if language is None:
            language = 'C'
        if encoding is None:
            options['locale'] = locale.normalize(language)
        else:
            options['locale'] = locale.normalize(language + '.' + encoding)

    if options['locale'].upper() in ('C', 'POSIX'):
        oldlocale = locale.setlocale(locale.LC_ALL)
        try:
            locale.setlocale(locale.LC_ALL, 'en_US.UTF-8')
            options['locale'] = 'en_US.UTF-8'
        except locale.Error:
            try:
                locale.setlocale(locale.LC_ALL, 'C.UTF-8')
                options['locale'] = 'C.UTF-8'
            except locale.Error:
                pass
        locale.setlocale(locale.LC_ALL, oldlocale)

    options['lang'] = options['locale']

    options['httpd_arguments_list'] = []

    options['trusted_proxy_headers'] = ' '.join(
            options['trusted_proxy_headers'])

    options['trusted_proxies'] = ' '.join(options['trusted_proxies'])

    if options['startup_log']:
        if not options['log_to_terminal']:
            options['startup_log_file'] = os.path.join(
                    options['log_directory'], options['startup_log_name'])
        else:
            try:
                with open('/dev/stderr', 'w'):
                    pass
            except IOError:
                try:
                    with open('/dev/tty', 'w'):
                        pass
                except IOError:
                    options['startup_log_file'] = None
                else:
                    options['startup_log_file'] = '/dev/tty'
            else:
                options['startup_log_file'] = '/dev/stderr'

        if options['startup_log_file']:
            options['httpd_arguments_list'].append('-E')
            options['httpd_arguments_list'].append(options['startup_log_file'])

    if options['verbose_debugging']:
        options['verbose_debugging_flag'] = 'On'
    else:
        options['verbose_debugging_flag'] = 'Off'

    if options['server_name']:
        host = options['server_name']
    else:
        host = options['host']

    options['server_host'] = host

    if options['port'] == 80:
        options['url'] = 'http://%s/' % host
    else:
        options['url'] = 'http://%s:%s/' % (host, options['port'])

    if options['https_port'] == 443:
        options['https_url'] = 'https://%s/' % host
    elif options['https_port'] is not None:
        options['https_url'] = 'https://%s:%s/' % (host, options['https_port'])
    else:
        options['https_url'] = None

    if any((options['enable_debugger'], options['enable_coverage'],
            options['enable_profiler'], options['enable_recorder'],
            options['enable_gdb'])):
        options['debug_mode'] = True

    if options['debug_mode']:
        options['httpd_arguments_list'].append('-DONE_PROCESS')

    if options['debug_mode']:
        if options['enable_coverage']:
            if not options['coverage_directory']:
                options['coverage_directory'] = os.path.join(
                        options['server_root'], 'htmlcov')
            else:
                options['coverage_directory'] = os.path.abspath(
                        options['coverage_directory'])

            try:
                os.mkdir(options['coverage_directory'])
            except Exception:
                pass

        if options['enable_profiler']:
            if not options['profiler_directory']:
                options['profiler_directory'] = os.path.join(
                        options['server_root'], 'pstats')
            else:
                options['profiler_directory'] = os.path.abspath(
                        options['profiler_directory'])

            try:
                os.mkdir(options['profiler_directory'])
            except Exception:
                pass

        if options['enable_recorder']:
            if not options['recorder_directory']:
                options['recorder_directory'] = os.path.join(
                        options['server_root'], 'archive')
            else:
                options['recorder_directory'] = os.path.abspath(
                        options['recorder_directory'])

            try:
                os.mkdir(options['recorder_directory'])
            except Exception:
                pass

    else:
        options['enable_debugger'] = False
        options['enable_coverage'] = False
        options['enable_profiler'] = False
        options['enable_recorder'] = False
        options['enable_gdb'] = False

    options['parent_domain'] = 'unspecified'

    if options['server_name']:
        options['httpd_arguments_list'].append('-DMOD_WSGI_VIRTUAL_HOST')
        if options['server_name'].lower().startswith('www.'):
            options['httpd_arguments_list'].append('-DMOD_WSGI_REDIRECT_WWW')
            options['parent_domain'] = options['server_name'][4:]

    if options['http2']: 
        options['httpd_arguments_list'].append('-DMOD_WSGI_WITH_HTTP2')
    if (options['https_port'] and options['ssl_certificate_file'] and
            options['ssl_certificate_key_file']):
        options['httpd_arguments_list'].append('-DMOD_WSGI_WITH_HTTPS')
    if options['ssl_ca_certificate_file']:
        options['httpd_arguments_list'].append('-DMOD_WSGI_VERIFY_CLIENT')
    if options['ssl_certificate_chain_file']:
        options['httpd_arguments_list'].append('-DMOD_WSGI_CERTIFICATE_CHAIN')

    if options['ssl_environment']:
        options['httpd_arguments_list'].append('-DMOD_WSGI_SSL_ENVIRONMENT')

    if options['https_only']:
        options['httpd_arguments_list'].append('-DMOD_WSGI_HTTPS_ONLY')
    if options['hsts_policy']:
        options['httpd_arguments_list'].append('-DMOD_WSGI_HSTS_POLICY')

    if options['server_aliases']:
        options['httpd_arguments_list'].append('-DMOD_WSGI_SERVER_ALIAS')
        options['server_aliases'] = ' '.join(options['server_aliases'])

    if options['allow_localhost']:
        options['httpd_arguments_list'].append('-DMOD_WSGI_ALLOW_LOCALHOST')

    if options['application_type'] == 'static':
        options['httpd_arguments_list'].append('-DMOD_WSGI_STATIC_ONLY')

    if options['server_metrics']:
        options['httpd_arguments_list'].append('-DMOD_WSGI_SERVER_METRICS')
    if options['server_status']:
        options['httpd_arguments_list'].append('-DMOD_WSGI_SERVER_METRICS')
        options['httpd_arguments_list'].append('-DMOD_WSGI_SERVER_STATUS')
    if options['directory_index']:
        options['httpd_arguments_list'].append('-DMOD_WSGI_DIRECTORY_INDEX')
    if options['directory_listing']:
        options['httpd_arguments_list'].append('-DMOD_WSGI_DIRECTORY_LISTING')
    if options['error_log_format']:
        options['httpd_arguments_list'].append('-DMOD_WSGI_ERROR_LOG_FORMAT')
    if options['access_log']:
        options['httpd_arguments_list'].append('-DMOD_WSGI_ACCESS_LOG')
    if options['rotate_logs']:
        options['httpd_arguments_list'].append('-DMOD_WSGI_ROTATE_LOGS')
    if options['keep_alive'] != 0:
        options['httpd_arguments_list'].append('-DMOD_WSGI_KEEP_ALIVE')
    if options['compress_responses'] != 0:
        options['httpd_arguments_list'].append('-DMOD_WSGI_COMPRESS_RESPONSES')
    if options['multiprocess']:
        options['httpd_arguments_list'].append('-DMOD_WSGI_MULTIPROCESS')
    if options['listener_host']:
        options['httpd_arguments_list'].append('-DMOD_WSGI_WITH_LISTENER_HOST')
    if options['error_override']:
        options['httpd_arguments_list'].append('-DMOD_WSGI_ERROR_OVERRIDE')
    if options['host_access_script']:
        options['httpd_arguments_list'].append('-DMOD_WSGI_HOST_ACCESS')
    if options['auth_user_script']:
        options['httpd_arguments_list'].append('-DMOD_WSGI_AUTH_USER')
    if options['auth_group_script']:
        options['httpd_arguments_list'].append('-DMOD_WSGI_AUTH_GROUP')
    if options['chunked_request']:
        options['httpd_arguments_list'].append('-DMOD_WSGI_CHUNKED_REQUEST')
    if options['with_php5']:
        options['httpd_arguments_list'].append('-DMOD_WSGI_WITH_PHP5')
    if options['proxy_mount_points'] or options['proxy_virtual_hosts']:
        options['httpd_arguments_list'].append('-DMOD_WSGI_WITH_PROXY')
    if options['trusted_proxy_headers']:
        options['httpd_arguments_list'].append('-DMOD_WSGI_WITH_PROXY_HEADERS')
    if options['trusted_proxies']:
        options['httpd_arguments_list'].append('-DMOD_WSGI_WITH_TRUSTED_PROXIES')
    if options['python_path']:
        options['httpd_arguments_list'].append('-DMOD_WSGI_WITH_PYTHON_PATH')

    if options['with_cgi']:
        if os.path.exists(os.path.join(options['modules_directory'],
                'mod_cgid.so')):
            options['httpd_arguments_list'].append('-DMOD_WSGI_CGID_SCRIPT')
        else:
            options['httpd_arguments_list'].append('-DMOD_WSGI_CGI_SCRIPT')

    options['httpd_arguments_list'].extend(
            _mpm_module_defines(options['modules_directory'],
            options['server_mpm_variables']))

    options['python_executable'] = sys.executable

    options['shlibpath_var'] = apxs_config.SHLIBPATH_VAR
    options['shlibpath'] = apxs_config.SHLIBPATH

    if _py_dylib:
        options['httpd_arguments_list'].append('-DMOD_WSGI_LOAD_PYTHON_DYLIB')

    options['python_dylib'] = _py_dylib

    options['httpd_arguments'] = '-f %s %s' % (options['httpd_conf'],
            ' '.join(options['httpd_arguments_list']))

    generate_wsgi_handler_script(options)

    if options['with_newrelic_platform']:
        generate_server_metrics_script(options)

    print('Server URL         :', options['url'])

    if options['https_url']:
        print('Server URL (HTTPS) :', options['https_url'])

    if options['server_status']:
        print('Server Status      :', '%sserver-status' % options['url'])

    print('Server Root        :', options['server_root'])
    print('Server Conf        :', options['httpd_conf'])

    print('Error Log File     : %s (%s)' % (options['error_log_file'],
            options['log_level']))

    if options['access_log']:
        print('Access Log File    :', options['access_log_file'])

    if options['startup_log']:
        print('Startup Log File   :', options['startup_log_file'])

    if options['enable_coverage']:
        print('Coverage Output    :', os.path.join(
                options['coverage_directory'], 'index.html'))

    if options['enable_profiler']:
        print('Profiler Output    :', options['profiler_directory'])

    if options['enable_recorder']:
        print('Recorder Output    :', options['recorder_directory'])

    if options['rewrite_rules']:
        print('Rewrite Rules      :', options['rewrite_rules'])

    if options['envvars_script']:
        print('Environ Variables  :', options['envvars_script'])

    if command == 'setup-server' or options['setup_only']:
        if not options['rewrite_rules']:
            print('Rewrite Rules      :', options['server_root'] + '/rewrite.conf')
        if not options['envvars_script']:
            print('Environ Variables  :', options['server_root'] + '/envvars')
        print('Control Script     :', options['server_root'] + '/apachectl')

    if options['processes'] == 1:
        print('Request Capacity   : %s (%s process * %s threads)' % (
                options['processes']*options['threads'],
                options['processes'], options['threads']))
    else:
        print('Request Capacity   : %s (%s processes * %s threads)' % (
                options['processes']*options['threads'],
                options['processes'], options['threads']))

    print('Request Timeout    : %s (seconds)' % options['request_timeout'])

    if options['startup_timeout']:
        print('Startup Timeout    : %s (seconds)' % options['startup_timeout'])

    print('Queue Backlog      : %s (connections)' % options['daemon_backlog'])

    print('Queue Timeout      : %s (seconds)' % options['queue_timeout'])

    print('Server Capacity    : %s (event/worker), %s (prefork)' % (
            options['worker_max_clients'], options['prefork_max_clients']))

    print('Server Backlog     : %s (connections)' % options['server_backlog'])

    print('Locale Setting     :', options['locale'])

    sys.stdout.flush()

    if not options['rewrite_rules']:
        options['rewrite_rules'] = options['server_root'] + '/rewrite.conf'

        if not os.path.isfile(options['rewrite_rules']):
            with open(options['rewrite_rules'], 'w') as fp:
                pass

    generate_apache_config(options)
    generate_control_scripts(options)

    return options

def cmd_start_server(params):
    formatter = optparse.IndentedHelpFormatter()
    formatter.set_long_opt_delimiter(' ')

    usage = '%prog start-server script [options]'
    parser = optparse.OptionParser(usage=usage, option_list=option_list,
            formatter=formatter)

    (options, args) = parser.parse_args(params)

    config = _cmd_setup_server('start-server', args, vars(options))

    if config['setup_only']:
        return

    executable = os.path.join(config['server_root'], 'apachectl')
    os.execl(executable, executable, 'start', '-DFOREGROUND')

def cmd_module_config(params):
    formatter = optparse.IndentedHelpFormatter()
    formatter.set_long_opt_delimiter(' ')

    usage = '%prog module-config'
    parser = optparse.OptionParser(usage=usage, formatter=formatter)

    (options, args) = parser.parse_args(params)

    if len(args) != 0:
        parser.error('Incorrect number of arguments.')

    if os.name == 'nt':
        real_prefix = getattr(sys, 'real_prefix', None)
        real_prefix = real_prefix or sys.prefix

        library_version = sysconfig.get_config_var('VERSION')

        library_name = 'python%s.dll' % library_version
        library_path = os.path.join(real_prefix, library_name)

        if not os.path.exists(library_path):
            library_name = 'python%s.dll' % library_version[0]
            library_path = os.path.join(real_prefix, 'DLLs', library_name)

        if not os.path.exists(library_path):
            library_path = None

        if library_path:
            library_path = os.path.normpath(library_path)
            library_path = library_path.replace('\\', '/')

            print('LoadFile "%s"' % library_path)

        module_path = where()
        module_path = module_path.replace('\\', '/')

        prefix = sys.prefix
        prefix = os.path.normpath(prefix)
        prefix = prefix.replace('\\', '/')

        print('LoadModule wsgi_module "%s"' % module_path)
        print('WSGIPythonHome "%s"' % prefix)

    else:
        module_path = where()

        prefix = sys.prefix
        prefix = os.path.normpath(prefix)

        if _py_dylib:
            print('LoadFile "%s"' % _py_dylib)

        print('LoadModule wsgi_module "%s"' % module_path)
        print('WSGIPythonHome "%s"' % prefix)

def cmd_install_module(params):
    formatter = optparse.IndentedHelpFormatter()
    formatter.set_long_opt_delimiter(' ')

    usage = '%prog install-module [options]'
    parser = optparse.OptionParser(usage=usage, formatter=formatter)

    parser.add_option('--modules-directory', metavar='DIRECTORY',
            default=apxs_config.LIBEXECDIR)

    (options, args) = parser.parse_args(params)

    if len(args) != 0:
        parser.error('Incorrect number of arguments.')

    target = os.path.abspath(os.path.join(options.modules_directory,
            os.path.basename(MOD_WSGI_SO)))

    shutil.copyfile(where(), target)

    if _py_dylib:
        print('LoadFile "%s"' % _py_dylib)
    print('LoadModule wsgi_module "%s"' % target)
    print('WSGIPythonHome "%s"' % os.path.normpath(sys.prefix))

def cmd_module_location(params):
    formatter = optparse.IndentedHelpFormatter()
    formatter.set_long_opt_delimiter(' ')

    usage = '%prog module-location'
    parser = optparse.OptionParser(usage=usage, formatter=formatter)

    (options, args) = parser.parse_args(params)

    if len(args) != 0:
        parser.error('Incorrect number of arguments.')

    print(where())

if os.name == 'nt':
    main_usage="""
    %prog command [params]

Commands:
    module-config
    module-location
"""
else:
    main_usage="""
    %prog command [params]

Commands:
    install-module
    module-config
    module-location
    setup-server
    start-server
"""

def main():
    parser = optparse.OptionParser(main_usage.strip())

    args = sys.argv[1:]

    if not args:
        parser.error('No command was specified.')

    command = args.pop(0)

    args = [os.path.expandvars(arg) for arg in args]

    if os.name == 'nt':
        if command == 'module-config':
            cmd_module_config(args)
        elif command == 'module-location':
            cmd_module_location(args)
        else:
            parser.error('Invalid command was specified.')
    else:
        if command == 'install-module':
            cmd_install_module(args)
        elif command == 'module-config':
            cmd_module_config(args)
        elif command == 'module-location':
            cmd_module_location(args)
        elif command == 'setup-server':
            cmd_setup_server(args)
        elif command == 'start-server':
            cmd_start_server(args)
        else:
            parser.error('Invalid command was specified.')

def start(*args):
    cmd_start_server(list(args))

if __name__ == '__main__':
    main()
