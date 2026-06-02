import os
import posixpath

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

<IfDefine MOD_WSGI_TELEMETRY_SERVICE>
WSGITelemetryService %(telemetry_service)s interval=%(telemetry_interval)s
</IfDefine>

<IfDefine MOD_WSGI_SLOW_REQUESTS>
WSGISlowRequests %(slow_requests)s
</IfDefine>

<IfDefine MOD_WSGI_SWITCH_INTERVAL>
WSGISwitchInterval %(switch_interval)s
</IfDefine>

<IfDefine MOD_WSGI_FREE_THREADING>
WSGIFreeThreading On
</IfDefine>

<IfDefine MOD_WSGI_TELEMETRY_OPTIONS>
%(telemetry_options)s
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

APACHE_PYTHON_WARNINGS_CONFIG = """
WSGIPythonWarnings '%(spec)s'
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

        if options['python_warnings']:
            for spec in options['python_warnings']:
                print(APACHE_PYTHON_WARNINGS_CONFIG % dict(spec=spec),
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
