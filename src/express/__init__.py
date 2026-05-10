import copy
import getpass
import inspect
import locale
import math
import optparse
import os
import posixpath
import pprint
import re
import shutil
import signal
import subprocess
import sys
import sysconfig
import tempfile
import time
import traceback
import types

from . import apxs_config
from .platform import find_program, MOD_WSGI_SO, PYTHON_DYLIB
from .options import option_list

APACHE_GENERAL_CONFIG = """
ServerName %(host)s
ServerRoot '%(server_root)s'
PidFile '%(pid_file)s'

DefaultRuntimeDir '%(server_root)s'

ServerTokens ProductOnly
ServerSignature Off

<IfDefine !MOD_WSGI_MPM_ENABLE_WINNT_MODULE>
User ${MOD_WSGI_USER}
Group ${MOD_WSGI_GROUP}
</IfDefine>

<IfDefine MOD_WSGI_WITH_LISTENER_HOST>
Listen %(host)s:%(port)s
</IfDefine>
<IfDefine !MOD_WSGI_WITH_LISTENER_HOST>
Listen %(port)s
</IfDefine>

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

<IfDefine MOD_WSGI_WITH_HTTP2>
LoadModule http2_module '${MOD_WSGI_MODULES_DIRECTORY}/mod_http2.so'
</IfDefine>

<IfModule !access_compat_module>
LoadModule access_compat_module '${MOD_WSGI_MODULES_DIRECTORY}/mod_access_compat.so'
</IfModule>
<IfDefine !MOD_WSGI_MPM_ENABLE_WINNT_MODULE>
<IfModule !unixd_module>
LoadModule unixd_module '${MOD_WSGI_MODULES_DIRECTORY}/mod_unixd.so'
</IfModule>
</IfDefine>
<IfModule !authn_core_module>
LoadModule authn_core_module '${MOD_WSGI_MODULES_DIRECTORY}/mod_authn_core.so'
</IfModule>
<IfModule !authz_core_module>
LoadModule authz_core_module '${MOD_WSGI_MODULES_DIRECTORY}/mod_authz_core.so'
</IfModule>

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

<IfModule !reqtimeout_module>
LoadModule reqtimeout_module '${MOD_WSGI_MODULES_DIRECTORY}/mod_reqtimeout.so'
</IfModule>

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

TypesConfig '%(mime_types)s'

HostnameLookups Off
MaxMemFree 64
Timeout %(socket_timeout)s
ListenBacklog %(server_backlog)s

<IfDefine MOD_WSGI_WITH_HTTP2>
Protocols h2 h2c http/1.1
</IfDefine>

RequestReadTimeout %(request_read_timeout)s

LimitRequestBody %(limit_request_body)s

<Directory />
    AllowOverride None
    Require all denied
</Directory>

WSGIPythonHome '%(python_home)s'

WSGIVerboseDebugging '%(verbose_debugging_flag)s'

<IfDefine !MOD_WSGI_MPM_ENABLE_WINNT_MODULE>
<IfDefine MOD_WSGI_WITH_SOCKET_PREFIX>
WSGISocketPrefix %(socket_prefix)s/wsgi
</IfDefine>
<IfDefine !MOD_WSGI_WITH_SOCKET_PREFIX>
WSGISocketPrefix %(server_root)s/wsgi
</IfDefine>
WSGISocketRotation Off
</IfDefine>

<IfDefine EMBEDDED_MODE>
MaxConnectionsPerChild %(maximum_requests)s
</IfDefine>

<IfDefine ORPHAN_INTERPRETER>
WSGIDestroyInterpreter Off
</IfDefine>
<IfDefine !ORPHAN_INTERPRETER>
WSGIDestroyInterpreter On
</IfDefine>

<IfDefine !ONE_PROCESS>
<IfDefine !EMBEDDED_MODE>
WSGIRestrictEmbedded On
<IfDefine MOD_WSGI_MULTIPROCESS>
WSGIDaemonProcess %(process_group)s \\
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
   interrupt-timeout=%(interrupt_timeout)s \\
   inactivity-timeout=%(inactivity_timeout)s \\
   startup-timeout=%(startup_timeout)s \\
   deadlock-timeout=%(deadlock_timeout)s \\
   graceful-timeout=%(graceful_timeout)s \\
   eviction-timeout=%(eviction_timeout)s \\
   restart-interval=%(restart_interval)s \\
   cpu-time-limit=%(cpu_time_limit)s \\
   shutdown-timeout=%(shutdown_timeout)s \\
   send-buffer-size=%(send_buffer_size)s \\
   receive-buffer-size=%(receive_buffer_size)s \\
   header-buffer-size=%(header_buffer_size)s \\
   response-buffer-size=%(response_buffer_size)s \\
   response-socket-timeout=%(response_socket_timeout)s \\
   server-metrics=%(server_metrics_flag)s%(daemon_switch_interval_option)s
</IfDefine>
<IfDefine !MOD_WSGI_MULTIPROCESS>
WSGIDaemonProcess %(process_group)s \\
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
   interrupt-timeout=%(interrupt_timeout)s \\
   inactivity-timeout=%(inactivity_timeout)s \\
   startup-timeout=%(startup_timeout)s \\
   deadlock-timeout=%(deadlock_timeout)s \\
   graceful-timeout=%(graceful_timeout)s \\
   eviction-timeout=%(eviction_timeout)s \\
   restart-interval=%(restart_interval)s \\
   cpu-time-limit=%(cpu_time_limit)s \\
   shutdown-timeout=%(shutdown_timeout)s \\
   send-buffer-size=%(send_buffer_size)s \\
   receive-buffer-size=%(receive_buffer_size)s \\
   response-buffer-size=%(response_buffer_size)s \\
   response-socket-timeout=%(response_socket_timeout)s \\
   server-metrics=%(server_metrics_flag)s%(daemon_switch_interval_option)s
</IfDefine>
</IfDefine>
</IfDefine>

WSGICallableObject '%(callable_object)s'
WSGIPassAuthorization On
WSGIMapHEADToGET %(map_head_to_get)s

<IfDefine MOD_WSGI_DISABLE_RELOADING>
WSGIScriptReloading Off
</IfDefine>

<IfDefine EMBEDDED_MODE>
<IfDefine MOD_WSGI_WITH_PYTHON_PATH>
WSGIPythonPath '%(python_path)s'
</IfDefine>
</IfDefine>

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

<IfDefine MOD_WSGI_METRICS_SERVICE>
WSGIMetricsService %(metrics_service)s interval=%(metrics_interval)s
</IfDefine>

<IfDefine MOD_WSGI_SLOW_REQUESTS>
WSGISlowRequests %(slow_requests)s
</IfDefine>

<IfDefine MOD_WSGI_SWITCH_INTERVAL>
WSGISwitchInterval %(switch_interval)s
</IfDefine>

<IfDefine MOD_WSGI_METRICS_OPTIONS>
%(metrics_options)s
</IfDefine>

<IfDefine MOD_WSGI_SERVER_STATUS>
<Location /server-status>
    SetHandler server-status
    Require all denied
    Require host localhost
</Location>
</IfDefine>

<IfDefine MOD_WSGI_KEEP_ALIVE>
KeepAlive On
KeepAliveTimeout %(keep_alive_timeout)s
</IfDefine>
<IfDefine !MOD_WSGI_KEEP_ALIVE>
KeepAlive Off
</IfDefine>

<IfDefine MOD_WSGI_ENABLE_SENDFILE>
EnableSendfile On
WSGIEnableSendfile On
</IfDefine>

<IfDefine MOD_WSGI_COMPRESS_RESPONSES>
AddOutputFilterByType DEFLATE text/plain
AddOutputFilterByType DEFLATE text/html
AddOutputFilterByType DEFLATE text/xml
AddOutputFilterByType DEFLATE text/css
AddOutputFilterByType DEFLATE text/javascript
AddOutputFilterByType DEFLATE application/xhtml+xml
AddOutputFilterByType DEFLATE application/javascript
AddOutputFilterByType DEFLATE application/json
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
MaxKeepAliveRequests %(prefork_max_keep_alive_requests)s
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
MaxKeepAliveRequests %(worker_max_keep_alive_requests)s
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
MaxKeepAliveRequests %(event_max_keep_alive_requests)s
ThreadStackSize 262144
</IfModule>

<IfDefine !MOD_WSGI_VIRTUAL_HOST>
<VirtualHost _default_:%(port)s>
</VirtualHost>
</IfDefine>

<IfDefine MOD_WSGI_VIRTUAL_HOST>

<VirtualHost _default_:%(port)s>
ServerName _wsgi_
<Location />
<IfDefine MOD_WSGI_ALLOW_LOCALHOST>
Require host localhost
</IfDefine>
<IfDefine !MOD_WSGI_ALLOW_LOCALHOST>
Require all denied
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
<VirtualHost _default_:%(https_port)s>
ServerName _wsgi_
<Location />
<IfDefine MOD_WSGI_ALLOW_LOCALHOST>
Require host localhost
</IfDefine>
<IfDefine !MOD_WSGI_ALLOW_LOCALHOST>
Require all denied
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

AccessFileName .htaccess

<Directory '%(server_root)s'>
    AllowOverride %(allow_override)s
<Files handler.wsgi>
    Require all granted
</Files>
</Directory>

<Directory '%(document_root)s'>
    AllowOverride %(allow_override)s
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
    RewriteOptions InheritDownBefore
    Include %(rewrite_rules)s
    Require all granted
</Directory>

<Directory '%(document_root)s%(mount_point)s'>
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
    <RequireAll>
    Require valid-user
<IfDefine MOD_WSGI_AUTH_GROUP>
    Require wsgi-group '%(auth_group)s'
</IfDefine>
    </RequireAll>
</Location>
</IfDefine>

<IfDefine !ONE_PROCESS>
<IfDefine !EMBEDDED_MODE>
WSGIHandlerScript wsgi-handler '%(server_root)s/handler.wsgi' \\
    process-group=%(process_group)s application-group=%(application_group)s
<IfDefine MOD_WSGI_IMPORT_HANDLER_SCRIPT>
WSGIImportScript '%(server_root)s/handler.wsgi' \\
    process-group=%(process_group)s application-group=%(application_group)s
</IfDefine>
</IfDefine>
</IfDefine>

<IfDefine EMBEDDED_MODE>
WSGIHandlerScript wsgi-handler '%(server_root)s/handler.wsgi' \\
    process-group='%%{GLOBAL}' application-group=%(application_group)s
<IfDefine MOD_WSGI_IMPORT_HANDLER_SCRIPT>
WSGIImportScript '%(server_root)s/handler.wsgi' \\
    process-group='%%{GLOBAL}' application-group=%(application_group)s
</IfDefine>
</IfDefine>

<IfDefine ONE_PROCESS>
<IfDefine !MOD_WSGI_MPM_ENABLE_WINNT_MODULE>
WSGIHandlerScript wsgi-handler '%(server_root)s/handler.wsgi' \\
    process-group='%%{GLOBAL}' application-group=%(application_group)s
<IfDefine MOD_WSGI_IMPORT_HANDLER_SCRIPT>
WSGIImportScript '%(server_root)s/handler.wsgi' \\
    process-group='%%{GLOBAL}' application-group=%(application_group)s
</IfDefine>
</IfDefine>
<IfDefine MOD_WSGI_MPM_ENABLE_WINNT_MODULE>
WSGIHandlerScript wsgi-handler '%(server_root)s/handler.wsgi' \\
    application-group=%(application_group)s
<IfDefine MOD_WSGI_IMPORT_HANDLER_SCRIPT>
WSGIImportScript '%(server_root)s/handler.wsgi' \\
    application-group=%(application_group)s
</IfDefine>
</IfDefine>
</IfDefine>
"""

APACHE_IGNORE_ACTIVITY_CONFIG = """
<Location '%(url)s'>
WSGIIgnoreActivity On
</Location>
"""

APACHE_PROXY_PASS_MOUNT_POINT_CONFIG = """
ProxyPass '%(mount_point)s' '%(url)s' upgrade=websocket
ProxyPassReverse '%(mount_point)s' '%(url)s'
<Location '%(mount_point)s'>
RewriteEngine On
RewriteRule .* - [E=SERVER_PORT:%%{SERVER_PORT},NE]
RequestHeader set X-Forwarded-Port %%{SERVER_PORT}e
RewriteCond %%{HTTPS} on
RewriteRule .* - [E=URL_SCHEME:https,NE]
RequestHeader set X-Forwarded-Scheme %%{URL_SCHEME}e env=URL_SCHEME
RequestHeader set X-Forwarded-Prefix %(prefix)s
</Location>
<LocationMatch '^%(prefix)s$'>
RewriteEngine On
RewriteRule .* http://%%{HTTP_HOST}%%{REQUEST_URI}/ [R=302,L]
</LocationMatch>
"""

APACHE_PROXY_PASS_MOUNT_POINT_SLASH_CONFIG = """
ProxyPass '%(mount_point)s/' '%(url)s/' upgrade=websocket
ProxyPassReverse '%(mount_point)s/' '%(url)s/'
<Location '%(mount_point)s/'>
RewriteEngine On
RewriteRule .* - [E=SERVER_PORT:%%{SERVER_PORT},NE]
RequestHeader set X-Forwarded-Port %%{SERVER_PORT}e
RewriteCond %%{HTTPS} on
RewriteRule .* - [E=URL_SCHEME:https,NE]
RequestHeader set X-Forwarded-Scheme %%{URL_SCHEME}e env=URL_SCHEME
RequestHeader set X-Forwarded-Prefix %(prefix)s
</Location>
<LocationMatch '^%(mount_point)s$'>
RewriteEngine On
RewriteRule .* http://%%{HTTP_HOST}%%{REQUEST_URI}/ [R=302,L]
</LocationMatch>
"""

APACHE_PROXY_PASS_HOST_CONFIG = """
<VirtualHost *:%(port)s>
ServerName %(host)s
ProxyPass / '%(url)s' upgrade=websocket
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
    AllowOverride %(allow_override)s
    Require all granted
</Directory>
"""

APACHE_ALIAS_FILENAME_CONFIG = """
Alias '%(mount_point)s' '%(directory)s/%(filename)s'

<Directory '%(directory)s'>
<Files '%(filename)s'>
    Require all granted
</Files>
</Directory>
"""

APACHE_ALIAS_DOCUMENTATION = """
Alias /__wsgi__/docs '%(documentation_directory)s'
Alias /__wsgi__/images '%(images_directory)s'

<Directory '%(documentation_directory)s'>
    DirectoryIndex index.html
    Require all granted
</Directory>

<Directory '%(images_directory)s'>
    Require all granted
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
<IfDefine !ONE_PROCESS>
<IfDefine !EMBEDDED_MODE>
WSGIHandlerScript wsgi-resource '%(server_root)s/resource.wsgi' \\
    process-group=%(process_group)s application-group=%%{GLOBAL}
</IfDefine>
<IfDefine EMBEDDED_MODE>
WSGIHandlerScript wsgi-resource '%(server_root)s/resource.wsgi' \\
    process-group='%%{GLOBAL}' application-group=%%{GLOBAL}
</IfDefine>
</IfDefine>

<IfDefine ONE_PROCESS>
<IfDefine !MOD_WSGI_MPM_ENABLE_WINNT_MODULE>
WSGIHandlerScript wsgi-resource '%(server_root)s/resource.wsgi' \\
    process-group='%%{GLOBAL}' application-group=%%{GLOBAL}
</IfDefine>
<IfDefine MOD_WSGI_MPM_ENABLE_WINNT_MODULE>
WSGIHandlerScript wsgi-resource '%(server_root)s/resource.wsgi' \\
    application-group=%%{GLOBAL}
</IfDefine>
</IfDefine>
"""

APACHE_HANDLER_CONFIG = """
AddHandler %(handler)s %(extension)s
"""

APACHE_INCLUDE_CONFIG = """
Include '%(filename)s'
"""


APACHE_SERVICE_CONFIG = """
WSGIDaemonProcess 'service:%(name)s' \\
    display-name=%%{GROUP} \\
    user='%(user)s' \\
    group='%(group)s' \\
    home='%(working_directory)s' \\
    threads=0 \\
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
    threads=0 \\
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

        if (options['proxy_timeout'] is not None and
                (options['proxy_mount_points'] or
                    options['proxy_virtual_hosts'])):
            print(f"ProxyTimeout {options['proxy_timeout']}", file=fp)

        if options['proxy_mount_points']:
            for mount_point, url in options['proxy_mount_points']:
                # X-Forwarded-Prefix is the conventional Traefik / Werkzeug /
                # Spring form: leading slash, no trailing slash. Strip any
                # user-supplied trailing slash so '/api' and '/api/' both
                # produce '/api'.
                prefix = str(mount_point).rstrip('/')
                if mount_point.endswith('/'):
                    print(APACHE_PROXY_PASS_MOUNT_POINT_CONFIG % dict(
                            mount_point=mount_point, url=url,
                            prefix=prefix), file=fp)
                else:
                    # Template forces a trailing "/" on both sides of the
                    # ProxyPass; strip any user-provided trailing slash on
                    # url so we end up single-slash terminated. Matters
                    # especially for unix-socket URLs of the form
                    # 'unix:/path|http://host/' where the trailing "/" is
                    # canonical.
                    print(APACHE_PROXY_PASS_MOUNT_POINT_SLASH_CONFIG % dict(
                            mount_point=mount_point,
                            url=str(url).rstrip('/'),
                            prefix=prefix), file=fp)

        if options['proxy_virtual_hosts']:
            for host, url in options['proxy_virtual_hosts']:
                print(APACHE_PROXY_PASS_HOST_CONFIG % dict(
                        host=host, port=options['port'], url=url),
                        file=fp)

        if options['url_aliases']:
            for mount_point, target in sorted(options['url_aliases'],
                    reverse=True):
                path = posixpath.abspath(target)

                if os.path.isdir(path) or not os.path.exists(path):
                    if target.endswith('/') and path != '/':
                        directory = path + '/'
                    else:
                        directory = path

                    print(APACHE_ALIAS_DIRECTORY_CONFIG % dict(
                            mount_point=mount_point, directory=directory,
                            allow_override=options['allow_override']),
                            file=fp)

                else:
                    directory = posixpath.dirname(path)
                    filename = posixpath.basename(path)

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
                filename = posixpath.abspath(filename)
                print(APACHE_INCLUDE_CONFIG % dict(filename=filename),
                        file=fp)

WSGI_HANDLER_SCRIPT = """
import os
import sys
import atexit
import time

from mod_wsgi.express.runtime import ApplicationHandler
from mod_wsgi.express.reloader import start_reloader

working_directory = r'%(working_directory)s'

entry_point = r'%(entry_point)s'
application_type = '%(application_type)s'
callable_object = '%(callable_object)s'
mount_point = '%(mount_point)s'
disable_reloading = %(disable_reloading)s
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

handler = ApplicationHandler(entry_point,
        application_type=application_type, callable_object=callable_object,
        mount_point=mount_point,
        debug_mode=debug_mode, enable_debugger=enable_debugger,
        debugger_startup=debugger_startup, enable_recorder=enable_recorder,
        recorder_directory=recorder_directory)

if not disable_reloading:
    reload_required = handler.reload_required

handle_request = handler.handle_request

if not disable_reloading and reload_on_changes and not debug_mode:
    start_reloader()
"""

WSGI_RESOURCE_SCRIPT = """
from mod_wsgi.express.runtime import ResourceHandler

resources = %(resources)s

handler = ResourceHandler(resources)

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

WSGI_CONTROL_SCRIPT = """
#!%(shell_executable)s

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

cd $MOD_WSGI_WORKING_DIRECTORY

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

def cmd_setup_server(params):
    formatter = optparse.IndentedHelpFormatter()
    formatter.set_long_opt_delimiter(' ')

    usage = '%prog setup-server script [options]'
    parser = optparse.OptionParser(usage=usage, option_list=option_list,
            formatter=formatter)

    (options, args) = parser.parse_args(params)

    try:
        _cmd_setup_server('setup-server', args, vars(options))
    except ConfigurationError as exc:
        parser.error(str(exc))

def _mpm_module_defines(modules_directory, preferred=None):
    if os.name == 'nt':
        return ['-DMOD_WSGI_MPM_ENABLE_WINNT_MODULE']

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

class ConfigurationError(Exception):
    pass

def _cmd_setup_server(command, args, options):
    options['sys_argv'] = repr(sys.argv)

    options['mod_wsgi_so'] = MOD_WSGI_SO

    options['working_directory'] = options['working_directory'] or os.getcwd()
    options['working_directory'] = os.path.abspath(options['working_directory'])

    if not options['host']:
        options['listener_host'] = None
        options['host'] = 'localhost'
    else:
        options['listener_host'] = options['host']

    if options['process_group']:
        options['daemon_name'] = '(wsgi:%s)' % options['process_group']
    elif os.name == 'nt':
        options['daemon_name'] = '(wsgi:%s:%s:%s)' % (options['host'],
            options['port'], getpass.getuser())
    else:
        options['daemon_name'] = '(wsgi:%s:%s:%s)' % (options['host'],
            options['port'], os.getuid())

    if not options['server_root']:
        if os.name == 'nt':
            tmpdir = tempfile.gettempdir()
        elif sys.platform == 'darwin':
            tmpdir = '/var/tmp'
        else:
            tmpdir = os.environ.get('TMPDIR')
            tmpdir = tmpdir or '/tmp'
            tmpdir = tmpdir.rstrip('/')

        if os.name == 'nt':
            options['server_root'] = ('%s/mod_wsgi-%s-%s-%s' % (tmpdir,
                    options['host'], options['port'], getpass.getuser())
                    ).replace('\\','/')
        else:
            options['server_root'] = '%s/mod_wsgi-%s:%s:%s' % (tmpdir,
                    options['host'], options['port'], os.getuid())

    if not os.path.isdir(options['server_root']):
        os.mkdir(options['server_root'])

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

    if (options['ssl_certificate_file'] or
            options['ssl_certificate_key_file'] or
            options['ssl_ca_certificate_file'] or
            options['ssl_certificate_chain_file']) and \
            not options['https_port']:
        raise ConfigurationError(
            '--https-port must be specified when SSL certificate '
            'options are provided.')

    if options['entry_point']:
        args = [options['entry_point']]

    if not args:
        if options['application_type'] != 'static':
            options['entry_point'] = posixpath.join(
                    options['server_root'], 'default.wsgi')
            options['application_type'] = 'script'
            options['enable_docs'] = True
        else:
            if not options['document_root']:
                options['document_root'] = os.getcwd()
            options['entry_point'] = '(static)'
    else:
        if options['application_type'] in ('script', 'paste'):
            options['entry_point'] = posixpath.abspath(args[0])
        elif options['application_type'] == 'static':
            if not options['document_root']:
                options['document_root'] = posixpath.abspath(args[0])
                options['entry_point'] = 'ignored'
            else:
                options['entry_point'] = 'overridden'
        else:
            options['entry_point'] = args[0]

    # Resolve --application-group into the literal token that the
    # generated config substitutes for the WSGI handler and import
    # scripts. Default leaves the application in the main interpreter
    # (%{GLOBAL}); a non-empty value is wrapped in single quotes so
    # the directive accepts arbitrary identifiers without the caller
    # needing to escape special characters.
    if options['application_group']:
        options['application_group'] = "'%s'" % options['application_group']
    else:
        options['application_group'] = '%{GLOBAL}'

    if options['process_group']:
        options['process_group'] = "'%s'" % options['process_group']
    else:
        options['process_group'] = "'%s:%s'" % (
                options['host'], options['port'])

    if options['host_access_script']:
        options['host_access_script'] = posixpath.abspath(
                options['host_access_script'])

    if options['auth_user_script']:
        options['auth_user_script'] = posixpath.abspath(
                options['auth_user_script'])

    if options['auth_group_script']:
        options['auth_group_script'] = posixpath.abspath(
                options['auth_group_script'])

    options['documentation_directory'] = os.path.join(os.path.dirname(
            os.path.dirname(__file__)), 'docs')
    options['images_directory'] = os.path.join(os.path.dirname(
            os.path.dirname(__file__)), 'images')

    if os.path.exists(posixpath.join(options['documentation_directory'],
            'index.html')):
        options['documentation_url'] = '/__wsgi__/docs/'
    else:
        options['documentation_url'] = 'http://www.modwsgi.org/'

    if not os.path.isabs(options['server_root']):
        options['server_root'] = posixpath.abspath(options['server_root'])

    if not options['document_root']:
        options['document_root'] = posixpath.join(options['server_root'],
                'htdocs')

    try:
        os.mkdir(options['document_root'])
    except Exception:
        pass

    if not options['allow_override']:
        options['allow_override'] = 'None'
    else:
        options['allow_override'] = ' '.join(options['allow_override'])

    if not options['mount_point'].startswith('/'):
        options['mount_point'] = posixpath.normpath('/' + options['mount_point'])

    # Create subdirectories for mount points in document directory
    # so that fallback resource rewrite rule will work.

    if options['mount_point'] != '/':
        parts = options['mount_point'].rstrip('/').split('/')[1:]
        subdir = options['document_root']
        try:
            for part in parts:
                subdir = posixpath.join(subdir, part)
                if not os.path.exists(subdir):
                    os.mkdir(subdir)
        except Exception:
            raise

    if not os.path.isabs(options['document_root']):
        options['document_root'] = posixpath.abspath(options['document_root'])

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
        options['log_directory'] = posixpath.abspath(options['log_directory'])

    if not options['log_to_terminal']:
        options['error_log_file'] = posixpath.join(options['log_directory'],
                options['error_log_name'])
    else:
        if os.name == 'nt':
            options['error_log_file'] = 'CON'
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
        options['access_log_file'] = posixpath.join(
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

    options['pid_file'] = ((options['pid_file'] and posixpath.abspath(
            options['pid_file'])) or posixpath.join(options['server_root'],
            'httpd.pid'))

    options['python_eggs'] = (posixpath.abspath(options['python_eggs']) if
            options['python_eggs'] is not None else None)

    if options['python_eggs'] is None:
        options['python_eggs'] = posixpath.join(options['server_root'],
                'python-eggs')

    try:
        os.mkdir(options['python_eggs'])
        if os.name != 'nt' and os.getuid() == 0:
            import grp
            import pwd
            os.chown(options['python_eggs'],
                    pwd.getpwnam(options['user']).pw_uid,
                    grp.getgrnam(options['group']).gr_gid)
    except Exception:
        pass

    if options['python_paths'] is None:
        options['python_paths'] = []

    if options['debug_mode'] or options['embedded_mode']:
        if options['working_directory'] not in options['python_paths']:
            options['python_paths'].insert(0, options['working_directory'])

    if options['debug_mode']:
        options['server_mpm_variables'] = ['worker', 'prefork']

    elif options['embedded_mode']:
        if not options['server_mpm_variables']:
            options['server_mpm_variables'] = ['worker', 'prefork']

    # Special case to check for when being executed from shiv variant
    # of a zipapp application bundle. We need to work out where the
    # site packages directory is and pass it with Python module search
    # path so is known about by the Apache sub process when executed.

    site_packages = []

    if '_bootstrap' in sys.modules:
        bootstrap = sys.modules['_bootstrap']
        if 'bootstrap' in dir(bootstrap):
            frame = inspect.currentframe()
            while frame is not None:
                code = frame.f_code
                if (code and code.co_filename == bootstrap.__file__ and
                        code.co_name == 'bootstrap' and
                        'site_packages' in frame.f_locals):
                    site_packages.append(str(frame.f_locals['site_packages']))
                    break
                frame = frame.f_back

    options['python_paths'].extend(site_packages)

    options['python_path'] = ':'.join(options['python_paths'])

    options['multiprocess'] = options['processes'] is not None
    options['processes'] = options['processes'] or 1

    options['python_home'] = sys.prefix.replace('\\','/')

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

    if options['metrics_service']:
        target = options['metrics_service']
        if not target.startswith('unix:'):
            raise ConfigurationError(
                "--metrics-service must be 'unix:/path' "
                "(remote 'udp:host:port' targets are no longer supported)")
    else:
        options['metrics_service'] = ''

    if options['slow_requests'] is not None:
        if options['slow_requests'] < 0:
            raise ConfigurationError(
                "--slow-requests threshold must be non-negative")
        if not options['metrics_service']:
            raise ConfigurationError(
                "--slow-requests requires --metrics-service")
    else:
        options['slow_requests'] = ''

    if options['switch_interval'] is not None:
        if options['switch_interval'] <= 0.0:
            raise ConfigurationError(
                "--switch-interval must be a positive number of seconds")
        options['daemon_switch_interval_option'] = (
            ' \\\n   switch-interval=%s' % options['switch_interval'])
    else:
        options['switch_interval'] = ''
        options['daemon_switch_interval_option'] = ''

    if options['handler_scripts']:
        handler_scripts = []
        for extension, script in options['handler_scripts']:
            if not os.path.isabs(script):
                script = posixpath.abspath(script)
            handler_scripts.append((extension, script))
        options['handler_scripts'] = handler_scripts

    if options['service_scripts']:
        service_scripts = []
        for name, script in options['service_scripts']:
            if not os.path.isabs(script):
                script = posixpath.abspath(script)
            service_scripts.append((name, script))
        options['service_scripts'] = service_scripts

    # Node that all the below calculations are overridden if are using
    # embedded mode.

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

    if options['embedded_mode']:
        max_clients = options['processes'] * options['threads']

        options['prefork_max_clients'] = max_clients
        options['prefork_server_limit'] = max_clients
        options['prefork_start_servers'] = max_clients
        options['prefork_min_spare_servers'] = max_clients
        options['prefork_max_spare_servers'] = max_clients

        options['worker_max_clients'] = max_clients
        options['worker_server_limit'] = options['processes']
        options['worker_thread_limit'] = options['threads']
        options['worker_threads_per_child'] = options['threads']
        options['worker_start_servers'] = options['processes']
        options['worker_min_spare_threads'] = max_clients
        options['worker_max_spare_threads'] = max_clients

    # Choose MaxKeepAliveRequests per MPM. The Apache core default is
    # 100 across all MPMs, but the cost of holding a long-lived
    # keep-alive connection differs sharply by MPM and by mod_wsgi
    # mode:
    #
    #   - event: idle keep-alive connections are parked on the listener
    #     thread and do not pin a worker, so an unlimited cap (0) is
    #     fine and avoids needless TCP/TLS handshake churn.
    #
    #   - worker / prefork in daemon mode: the MPM child that accepts
    #     a connection is just a multiplexer and the actual Python
    #     work is dispatched per-request to the daemon pool, so
    #     connection-pinning at the MPM layer does not translate to
    #     daemon-side pinning. The cap is purely TCP / connection
    #     hygiene; raising it modestly above the Apache default
    #     amortises handshakes for clients that send many requests.
    #
    #   - worker / prefork in embedded mode: the MPM child IS the
    #     Python worker, so the cap is a fairness knob bounding how
    #     long one keep-alive client can hold a worker slot away from
    #     other clients. The static-asset case argues for a high cap
    #     and the slow-Python-request case argues for a low one;
    #     Apache's default of 100 is left in place as a defensible
    #     compromise.
    #
    # mpm_winnt and any third-party MPM are not matched by the
    # IfModule blocks in the generated config, so they fall through
    # to Apache's core default of 100. That outcome is intentional:
    # without an empirical basis for tuning a non-listed MPM the
    # safe choice is to inherit the upstream default.
    options['event_max_keep_alive_requests'] = 0
    if options['embedded_mode']:
        options['prefork_max_keep_alive_requests'] = 100
        options['worker_max_keep_alive_requests'] = 100
    else:
        options['prefork_max_keep_alive_requests'] = 500
        options['worker_max_keep_alive_requests'] = 500

    options['httpd_conf'] = posixpath.join(options['server_root'], 'httpd.conf')

    options['httpd_executable'] = os.environ.get('HTTPD',
            options['httpd_executable'])

    if os.name != 'nt':
        if not os.path.isabs(options['httpd_executable']):
            options['httpd_executable'] = find_program(
                    [options['httpd_executable']], 'httpd', ['/usr/sbin'])

    if not options['process_name']:
        options['process_name'] = posixpath.basename(
                options['httpd_executable']) + ' (mod_wsgi-express)'

    options['process_name'] = options['process_name'].ljust(
            len(options['daemon_name']))

    options['rewrite_rules'] = (posixpath.abspath(
            options['rewrite_rules']) if options['rewrite_rules'] is
            not None else None)

    options['envvars_script'] = (posixpath.abspath(
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
            options['startup_log_file'] = posixpath.join(
                    options['log_directory'], options['startup_log_name'])
        else:
            if os.name == 'nt':
                options['startup_log_file'] = 'CON'
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

    if options['orphan_interpreter']:
        options['httpd_arguments_list'].append('-DORPHAN_INTERPRETER')

    if options['embedded_mode']:
        options['httpd_arguments_list'].append('-DEMBEDDED_MODE')
        options['disable_reloading'] = True

    # %{GLOBAL} is a mod_wsgi sentinel for the main interpreter, not a
    # request-time variable expansion; any other %{...} resolves per
    # request and so cannot be pre-imported into a fixed sub-interpreter.
    if (options['application_group'] == '%{GLOBAL}'
            or '%{' not in options['application_group']):
        options['httpd_arguments_list'].append('-DMOD_WSGI_IMPORT_HANDLER_SCRIPT')

    if options['debugger_startup'] and not options['enable_debugger']:
        raise ConfigurationError(
            "--debugger-startup requires --enable-debugger")

    if any((options['enable_debugger'], options['enable_coverage'],
            options['enable_profiler'], options['enable_recorder'],
            options['enable_gdb'])):
        options['debug_mode'] = True

    if options['debug_mode']:
        options['httpd_arguments_list'].append('-DONE_PROCESS')

    if options['debug_mode']:
        if options['enable_coverage']:
            if not options['coverage_directory']:
                options['coverage_directory'] = posixpath.join(
                        options['server_root'], 'htmlcov')
            else:
                options['coverage_directory'] = posixpath.abspath(
                        options['coverage_directory'])

            try:
                os.mkdir(options['coverage_directory'])
            except Exception:
                pass

        if options['enable_profiler']:
            if not options['profiler_directory']:
                options['profiler_directory'] = posixpath.join(
                        options['server_root'], 'pstats')
            else:
                options['profiler_directory'] = posixpath.abspath(
                        options['profiler_directory'])

            try:
                os.mkdir(options['profiler_directory'])
            except Exception:
                pass

        if options['enable_recorder']:
            if not options['recorder_directory']:
                options['recorder_directory'] = posixpath.join(
                        options['server_root'], 'archive')
            else:
                options['recorder_directory'] = posixpath.abspath(
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

    if options['enable_sendfile']:
        options['httpd_arguments_list'].append('-DMOD_WSGI_ENABLE_SENDFILE')

    if options['server_metrics']:
        options['httpd_arguments_list'].append('-DMOD_WSGI_SERVER_METRICS')
    if options['server_status']:
        options['httpd_arguments_list'].append('-DMOD_WSGI_SERVER_METRICS')
        options['httpd_arguments_list'].append('-DMOD_WSGI_SERVER_STATUS')
    if options['metrics_service']:
        options['httpd_arguments_list'].append('-DMOD_WSGI_METRICS_SERVICE')
    if options['slow_requests'] != '':
        options['httpd_arguments_list'].append('-DMOD_WSGI_SLOW_REQUESTS')
    if options['switch_interval'] != '':
        options['httpd_arguments_list'].append('-DMOD_WSGI_SWITCH_INTERVAL')
    if options['metrics_options']:
        options['httpd_arguments_list'].append('-DMOD_WSGI_METRICS_OPTIONS')
        options['metrics_options'] = '\n'.join(
            'WSGIMetricsOptions %s' % v for v in options['metrics_options'])
    else:
        options['metrics_options'] = ''
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
    if options['socket_prefix']:
        options['httpd_arguments_list'].append('-DMOD_WSGI_WITH_SOCKET_PREFIX')
    if options['disable_reloading']:
        options['httpd_arguments_list'].append('-DMOD_WSGI_DISABLE_RELOADING')

    if options['with_cgi']:
        if os.path.exists(posixpath.join(options['modules_directory'],
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

    if PYTHON_DYLIB:
        options['httpd_arguments_list'].append('-DMOD_WSGI_LOAD_PYTHON_DYLIB')

    options['python_dylib'] = PYTHON_DYLIB

    options['httpd_arguments'] = '-f %s %s' % (options['httpd_conf'],
            ' '.join(options['httpd_arguments_list']))

    generate_wsgi_handler_script(options)

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
        print('Coverage Output    :', posixpath.join(
                options['coverage_directory'], 'index.html'))

    if options['enable_profiler']:
        print('Profiler Output    :', options['profiler_directory'])

    if options['enable_recorder']:
        print('Recorder Output    :', options['recorder_directory'])

    if options['rewrite_rules']:
        print('Rewrite Rules      :', options['rewrite_rules'])

    if os.name != 'nt':
        if options['envvars_script']:
            print('Environ Variables  :', options['envvars_script'])

    if command == 'setup-server' or options['setup_only']:
        if not options['rewrite_rules']:
            print('Rewrite Rules      :', options['server_root'] + '/rewrite.conf')
        if os.name != 'nt':
            if not options['envvars_script']:
                print('Environ Variables  :', options['server_root'] + '/envvars')
            print('Control Script     :', options['server_root'] + '/apachectl')

    if options['debug_mode']:
        print('Operating Mode     : debug')
    elif options['embedded_mode']:
        print('Operating Mode     : embedded')
    else:
        print('Operating Mode     : daemon')

    if options['processes'] == 1:
        print('Request Capacity   : %s (%s process * %s threads)' % (
                options['processes']*options['threads'],
                options['processes'], options['threads']))
    else:
        print('Request Capacity   : %s (%s processes * %s threads)' % (
                options['processes']*options['threads'],
                options['processes'], options['threads']))

    if not options['debug_mode'] and not options['embedded_mode']:
        print('Request Timeout    : %s (seconds)' % options['request_timeout'])

        if options['interrupt_timeout']:
            print('Interrupt Timeout  : %s (seconds)' % options['interrupt_timeout'])

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

    if os.name != 'nt':
        generate_control_scripts(options)

    return options

def cmd_start_server(params):
    formatter = optparse.IndentedHelpFormatter()
    formatter.set_long_opt_delimiter(' ')

    usage = '%prog start-server script [options]'
    parser = optparse.OptionParser(usage=usage, option_list=option_list,
            formatter=formatter)

    (options, args) = parser.parse_args(params)

    try:
        config = _cmd_setup_server('start-server', args, vars(options))
    except ConfigurationError as exc:
        parser.error(str(exc))

    if config['setup_only']:
        return

    if os.name == 'nt':
        print()
        print("WARNING: The ability to use the start-server option on Windows")
        print("WARNING: is highly experimental and various things don't quite")
        print("WARNING: work properly. If you understand a lot about using")
        print("WARNING: Python on Windows and Windows programming in general,")
        print("WARNING: and would like to help to get it working properly, then")
        print("WARNING: you can ask about Windows support for the start-server")
        print("WARNING: option on the mod_wsgi mailing list.")
        print()

        executable = config['httpd_executable']

        environ = copy.deepcopy(os.environ)

        environ['MOD_WSGI_MODULES_DIRECTORY'] = config['modules_directory']

        httpd_arguments = list(config['httpd_arguments_list'])
        httpd_arguments.extend(['-f', config['httpd_conf']])
        httpd_arguments.extend(['-DONE_PROCESS'])

        os.environ['MOD_WSGI_MODULES_DIRECTORY'] = config['modules_directory']

        subprocess.call([executable]+httpd_arguments)

        sys.exit(0)

    else:
        executable = posixpath.join(config['server_root'], 'apachectl')

        if sys.stdout.isatty() and not config['debug_mode']:
            process = None

            def handler(signum, frame):
                if process is None:
                    sys.exit(1)

                else:
                    if signum not in [signal.SIGWINCH]:
                        os.kill(process.pid, signum)

            signal.signal(signal.SIGINT, handler)
            signal.signal(signal.SIGTERM, handler)
            signal.signal(signal.SIGHUP, handler)
            signal.signal(signal.SIGUSR1, handler)
            signal.signal(signal.SIGWINCH, handler)

            process = subprocess.Popen([executable, 'start', '-DFOREGROUND'],
                    preexec_fn=os.setpgrp)

            process.wait()

        else:
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
        base_prefix = getattr(sys, 'base_prefix', None)

        real_prefix = real_prefix or base_prefix or sys.prefix

        library_version = sysconfig.get_config_var('VERSION')

        library_name = 'python%s.dll' % library_version
        library_path = posixpath.join(real_prefix, library_name)

        if not os.path.exists(library_path):
            library_name = 'python%s.dll' % library_version[0]
            library_path = posixpath.join(real_prefix, 'DLLs', library_name)

        if not os.path.exists(library_path):
            library_path = None

        if library_path:
            library_path = posixpath.normpath(library_path)
            library_path = library_path.replace('\\', '/')

            print('LoadFile "%s"' % library_path)

        module_path = MOD_WSGI_SO
        module_path = module_path.replace('\\', '/')

        prefix = sys.prefix
        prefix = posixpath.normpath(prefix)
        prefix = prefix.replace('\\', '/')

        print('LoadModule wsgi_module "%s"' % module_path)
        print('WSGIPythonHome "%s"' % prefix)

    else:
        module_path = MOD_WSGI_SO

        prefix = sys.prefix
        prefix = posixpath.normpath(prefix)

        if PYTHON_DYLIB:
            print('LoadFile "%s"' % PYTHON_DYLIB)

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

    target = posixpath.abspath(posixpath.join(options.modules_directory,
            posixpath.basename(MOD_WSGI_SO)))

    shutil.copyfile(MOD_WSGI_SO, target)

    if PYTHON_DYLIB:
        print('LoadFile "%s"' % PYTHON_DYLIB)
    print('LoadModule wsgi_module "%s"' % target)
    print('WSGIPythonHome "%s"' % posixpath.normpath(sys.prefix))

def cmd_module_location(params):
    formatter = optparse.IndentedHelpFormatter()
    formatter.set_long_opt_delimiter(' ')

    usage = '%prog module-location'
    parser = optparse.OptionParser(usage=usage, formatter=formatter)

    (options, args) = parser.parse_args(params)

    if len(args) != 0:
        parser.error('Incorrect number of arguments.')

    print(MOD_WSGI_SO)

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
        elif command == 'start-server':
            cmd_start_server(args)
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
