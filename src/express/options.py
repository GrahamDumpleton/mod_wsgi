import optparse
import os

from . import apxs_config
from .platform import (
    SHELL, default_run_group, default_run_user, find_mimetypes,
)

def check_percentage(option, opt_str, value, parser):
    if value is not None and value < 0 or value > 1:
        raise optparse.OptionValueError('%s option value needs to be within '
                'the range 0 to 1.' % opt_str)
    setattr(parser.values, option.dest, value)

option_list = []

def add_option(platforms, *args, **kwargs):
    targets = platforms.split('|')

    suppress = False

    if os.name == 'nt':
        if 'all' not in targets and 'windows' not in targets:
            suppress = True
    else:
        if 'all' not in targets and 'unix' not in targets:
            suppress = True

    if suppress:
        kwargs['help'] = optparse.SUPPRESS_HELP

    if 'hidden' in targets:
        kwargs['help'] = optparse.SUPPRESS_HELP

    option_list.append(optparse.make_option(*args, **kwargs))

add_option('all', '--application-type', default='script',
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
        'directory if none is supplied.')

add_option('all', '--entry-point', default=None,
        metavar='FILE-PATH|MODULE', help='The file system path or '
        'module name identifying the file which contains the WSGI '
        'application entry point. How the value given is interpreted '
        'depends on the corresponding type identified using the '
        '\'--application-type\' option. Use of this option is the '
        'same as if the value had been given as argument but without '
        'any option specifier. A named option is also provided so '
        'as to make it clearer in a long option list what the entry '
        'point actually is. If both methods are used, that specified '
        'by this option will take precedence.')

add_option('all', '--application-group', default=None,
        metavar='NAME', help='Override the WSGI application group used '
        'for the generated WSGI handler directives. The default is the '
        '%{GLOBAL} token, which places the WSGI application in the '
        'Python main interpreter. Setting this to a name routes the '
        'application into a named sub-interpreter instead.')

add_option('all', '--process-group', default=None,
        metavar='NAME', help='Override the WSGI daemon process group '
        'name used in the generated configuration. The default uses '
        'the listening host and port as the group name. Has no effect '
        'under --embedded-mode. Useful when a stable, recognisable '
        'name is wanted, for example for signal-driven recycling via '
        'pkill against a known wsgi:NAME process name.')

add_option('all', '--host', default=None, metavar='IP-ADDRESS',
        help='The specific host (IP address) interface on which '
        'requests are to be accepted. Defaults to listening on '
        'all host interfaces.')

add_option('all', '--port', default=8000, type='int',
        metavar='NUMBER', help='The specific port to bind to and '
        'on which requests are to be accepted. Defaults to port 8000.')

add_option('all', '--http2', action='store_true', default=False,
        help='Flag indicating whether HTTP/2 should be enabled.'
        'Requires the mod_http2 module to be available.')

add_option('all', '--https-port', type='int', metavar='NUMBER',
        help='The specific port to bind to and on which secure '
        'requests are to be accepted.')

add_option('all', '--ssl-port', type='int', metavar='NUMBER',
        dest='https_port', help=optparse.SUPPRESS_HELP)

add_option('all', '--ssl-certificate-file', default=None,
        metavar='FILE-PATH', help='Specify the path to the SSL '
        'certificate file.')

add_option('all', '--ssl-certificate-key-file', default=None,
        metavar='FILE-PATH', help='Specify the path to the private '
        'key file corresponding to the SSL certificate file.')

add_option('all', '--ssl-certificate', default=None,
        metavar='FILE-PATH', help='Specify the common path to the SSL '
        'certificate files. This is a convenience function so that '
        'only one option is required to specify the location of the '
        'certificate file and the private key file. It is expected that '
        'the files have \'.crt\' and \'.key\' extensions. This option '
        'should refer to the common part of the names for both files '
        'which appears before the extension.')

add_option('all', '--ssl-ca-certificate-file', default=None,
        metavar='FILE-PATH', help='Specify the path to the file with '
        'the CA certificates to be used for client authentication. When '
        'specified, access to the whole site will by default require '
        'client authentication. To require client authentication for '
        'only parts of the site, use the --ssl-verify-client option.')

add_option('all', '--ssl-verify-client', action='append',
        metavar='URL-PATH', dest='ssl_verify_client_urls',
        help='Specify a sub URL of the site for which client '
        'authentication is required. When this option is specified, '
        'the default of client authentication being required for the '
        'whole site will be disabled and verification will only be '
        'required for the specified sub URL.')

add_option('all', '--ssl-certificate-chain-file', default=None,
        metavar='FILE-PATH', help='Specify the path to a file '
        'containing the certificates of Certification Authorities (CA) '
        'which form the certificate chain of the server certificate.')

add_option('all', '--ssl-environment', action='store_true',
        default=False, help='Flag indicating whether the standard set '
        'of SSL related variables are passed in the per request '
        'environment passed to a handler.')

add_option('all', '--https-only', action='store_true',
        default=False, help='Flag indicating whether any requests '
        'made using a HTTP request over the non secure connection '
        'should be redirected automatically to use a HTTPS request '
        'over the secure connection.')

add_option('all', '--hsts-policy', default=None, metavar='PARAMS',
        help='Specify the HSTS policy that should be applied when '
        'HTTPS only connections are being enforced.')

add_option('all', '--server-name', default=None, metavar='HOSTNAME',
        help='The primary host name of the web server. If this name '
        'starts with \'www.\' then an automatic redirection from the '
        'parent domain name to the \'www.\' server name will created.')

add_option('all', '--server-alias', action='append',
        dest='server_aliases', metavar='HOSTNAME', help='A secondary '
        'host name for the web server. May include wildcard patterns.')

add_option('all', '--allow-localhost', action='store_true',
        default=False, help='Flag indicating whether access via '
        'localhost should still be allowed when a server name has been '
        'specified and a name based virtual host has been configured.')

add_option('unix', '--processes', type='int', metavar='NUMBER',
        help='The number of worker processes (instances of the WSGI '
        'application) to be started up and which will handle requests '
        'concurrently. Defaults to a single process.')

add_option('all', '--threads', type='int', default=5, metavar='NUMBER',
        help='The number of threads in the request thread pool of '
        'each process for handling requests. Defaults to 5 in each '
        'process. Note that if embedded mode and only prefork MPM '
        'is available, then processes will instead be used.')

add_option('unix', '--max-clients', type='int', default=None,
        metavar='NUMBER', help='The maximum number of simultaneous '
        'client connections that will be accepted. This will default '
        'to being 1.5 times the total number of threads in the '
        'request thread pools across all process handling requests. '
        'Note that if embedded mode is used this will be ignored.')

add_option('unix', '--initial-workers', type='float', default=None,
        metavar='NUMBER', action='callback', callback=check_percentage,
        help='The initial number of workers to create on startup '
        'expressed as a percentage of the maximum number of clients. '
        'The value provided should be between 0 and 1. The default is '
        'dependent on the type of MPM being used. Note that if '
        'embedded mode is used, this will be ignored.'),

add_option('unix', '--minimum-spare-workers', type='float',
        default=None, metavar='NUMBER', action='callback',
        callback=check_percentage, help='The minimum number of spare '
        'workers to maintain expressed as a percentage of the maximum '
        'number of clients. The value provided should be between 0 and '
        '1. The default is dependent on the type of MPM being used. '
        'Note that if embedded mode is used, this will be ignored.')

add_option('unix', '--maximum-spare-workers', type='float',
        default=None, metavar='NUMBER', action='callback',
        callback=check_percentage, help='The maximum number of spare '
        'workers to maintain expressed as a percentage of the maximum '
        'number of clients. The value provided should be between 0 and '
        '1. The default is dependent on the type of MPM being used. '
        'Note that if embedded mode is used, this will be ignored.')

add_option('all', '--limit-request-body', type='int', default=10485760,
        metavar='NUMBER', help='The maximum number of bytes which are '
        'allowed in a request body. Defaults to 10485760 (10MB).')

add_option('all', '--maximum-requests', type='int', default=0,
        metavar='NUMBER', help='The number of requests after which '
        'any one worker process will be restarted and the WSGI '
        'application reloaded. Defaults to 0, indicating that the '
        'worker process should never be restarted based on the number '
        'of requests received.')

add_option('unix', '--startup-timeout', type='int', default=15,
        metavar='SECONDS', help='Maximum number of seconds allowed '
        'to pass waiting for the application to be successfully '
        'loaded and started by a worker process. When this timeout '
        'has been reached without the application having been '
        'successfully loaded and started, the worker process will '
        'be forced to restart. Defaults to 15 seconds.')

add_option('unix', '--shutdown-timeout', type='int', default=5,
        metavar='SECONDS', help='Maximum number of seconds allowed '
        'to pass when waiting for a worker process to shutdown as a '
        'result of the maximum number of requests or inactivity timeout '
        'being reached, or when a user initiated SIGINT signal is sent '
        'to a worker process. When this timeout has been reached the '
        'worker process will be forced to exit even if there are '
        'still active requests or it is still running Python exit '
        'functions. Defaults to 5 seconds.')

add_option('unix', '--restart-interval', type='int', default='0',
        metavar='SECONDS', help='Number of seconds between worker '
        'process restarts. If graceful timeout is also specified, '
        'active requests will be given a chance to complete before '
        'the process is forced to exit and restart. Not enabled by '
        'default.')

add_option('unix', '--cpu-time-limit', type='int', default='0',
        metavar='SECONDS', help='Number of seconds of CPU time the '
        'process can use before it will be restarted. If graceful '
        'timeout is also specified, active requests will be given '
        'a chance to complete before the process is forced to exit '
        'and restart. Not enabled by default.')

add_option('unix', '--graceful-timeout', type='int', default=15,
        metavar='SECONDS', help='Grace period for requests to complete '
        'normally, while still accepting new requests, when worker '
        'processes are being shutdown and restarted due to maximum '
        'requests being reached or restart interval having expired. '
        'Defaults to 15 seconds.')

add_option('unix', '--eviction-timeout', type='int', default=0,
        metavar='SECONDS', help='Grace period for requests to complete '
        'normally, while still accepting new requests, when the WSGI '
        'application is being evicted from the worker processes, and '
        'the process restarted, due to forced graceful restart signal. '
        'Defaults to timeout specified by \'--graceful-timeout\' '
        'option.')

add_option('unix', '--deadlock-timeout', type='int', default=60,
        metavar='SECONDS', help='Maximum number of seconds allowed '
        'to pass before the worker process is forcibly shutdown and '
        'restarted after a potential deadlock on the Python GIL has '
        'been detected. Defaults to 60 seconds.')

add_option('unix', '--inactivity-timeout', type='int', default=0,
        metavar='SECONDS', help='Maximum number of seconds allowed '
        'to pass before the worker process is shutdown and restarted '
        'when the worker process has entered an idle state and is no '
        'longer receiving new requests. Not enabled by default.')

add_option('unix', '--ignore-activity', action='append',
        dest='ignore_activity', metavar='URL-PATH', help='Specify '
        'the URL path for any location where activity should be '
        'ignored when the \'--activity-timeout\' option is used. '
        'This would be used on health check URLs so that health '
        'checks do not prevent process restarts due to inactivity.')

add_option('unix', '--request-timeout', type='int', default=60,
        metavar='SECONDS', help='Per-thread upper bound for how long a '
        'request can run before recovery is triggered. The actual fire '
        'point scales with thread count by natural log: '
        'request-timeout * (1 + ln(threads)). At threads=1 this collapses '
        'to request-timeout; at threads=10 it is ~3.3x; at threads=25 it '
        'is ~4.2x. Recovery is either RequestTimeout injection (if '
        '--interrupt-timeout is non-zero) or graceful-timeout followed '
        'by shutdown-timeout. Defaults to 60 seconds.')

add_option('unix', '--interrupt-timeout', type='int', default=0,
        metavar='SECONDS', help='When non-zero, attempts to interrupt only '
        'the wedged thread when request-timeout fires by injecting a '
        'mod_wsgi.RequestTimeout exception (subclass of BaseException) into '
        'it. If the injection unwinds the stuck request before this many '
        'seconds elapse, the WSGI adapter returns 504 Gateway Timeout and '
        'the worker thread continues serving further requests; otherwise '
        'the daemon process falls through to graceful-timeout and then '
        'shutdown-timeout. Detection is unaffected by this setting; only '
        'the recovery method changes. Defaults to 0 (disabled).')

add_option('unix', '--connect-timeout', type='int', default=15,
        metavar='SECONDS', help='Maximum number of seconds allowed '
        'to pass before giving up on attempting to get a connection '
        'to the worker process from the Apache child process which '
        'accepted the request. This comes into play when the worker '
        'listener backlog limit is exceeded. Defaults to 15 seconds.')

add_option('all', '--socket-timeout', type='int', default=60,
        metavar='SECONDS', help='Maximum number of seconds allowed '
        'to pass before timing out on a read or write operation on '
        'a socket and aborting the request. Defaults to 60 seconds.')

add_option('all', '--proxy-timeout', type='int', default=None,
        metavar='SECONDS', help='Override the timeout used for connections '
        'to a proxied backend (Apache ProxyTimeout directive). When unset '
        'this falls back to --socket-timeout. Raise it for backends with '
        'idle WebSocket clients that do not heartbeat more often than '
        '--socket-timeout, since otherwise idle WebSocket connections will '
        'be dropped at that interval.')

add_option('all', '--queue-timeout', type='int', default=45,
        metavar='SECONDS', help='Maximum number of seconds allowed '
        'for a request to be accepted by a worker process to be '
        'handled, taken from the time when the Apache child process '
        'originally accepted the request. Defaults to 45 seconds.')

add_option('all', '--header-timeout', type='int', default=15,
        metavar='SECONDS', help='The number of seconds allowed for '
        'receiving the request including the headers. This may be '
        'dynamically increased if a minimum rate for reading the '
        'request and headers is also specified, up to any limit '
        'imposed by a maximum header timeout. Defaults to 15 seconds.')

add_option('all', '--header-max-timeout', type='int', default=30,
        metavar='SECONDS', help='Maximum number of seconds allowed for '
        'receiving the request including the headers. This is the hard '
        'limit after taking into consideration and increases to the '
        'basic timeout due to minimum rate for reading the request and '
        'headers which may be specified. Defaults to 30 seconds.')

add_option('all', '--header-min-rate', type='int', default=500,
        metavar='BYTES', help='The number of bytes required to be sent '
        'as part of the request and headers to trigger a dynamic '
        'increase in the timeout on receiving the request including '
        'headers. Each time this number of bytes is received the timeout '
        'will be increased by 1 second up to any maximum specified by '
        'the maximum header timeout. Defaults to 500 bytes.')

add_option('all', '--body-timeout', type='int', default=15,
        metavar='SECONDS', help='The number of seconds allowed for '
        'receiving the request body. This may be dynamically increased '
        'if a minimum rate for reading the request body is also '
        'specified, up to any limit imposed by a maximum body timeout. '
        'Defaults to 15 seconds.')

add_option('all', '--body-max-timeout', type='int', default=0,
        metavar='SECONDS', help='Maximum number of seconds allowed for '
        'receiving the request body. This is the hard limit after '
        'taking into consideration and increases to the basic timeout '
        'due to minimum rate for reading the request body which may be '
        'specified. Defaults to 0 indicating there is no maximum.')

add_option('all', '--body-min-rate', type='int', default=500,
        metavar='BYTES', help='The number of bytes required to be sent '
        'as part of the request body to trigger a dynamic increase in '
        'the timeout on receiving the request body. Each time this '
        'number of bytes is received the timeout will be increased '
        'by 1 second up to any maximum specified by the maximum body '
        'timeout. Defaults to 500 bytes.')

add_option('all', '--server-backlog', type='int', default=500,
        metavar='NUMBER', help='Depth of server socket listener '
        'backlog for Apache child processes. Defaults to 500.')

add_option('unix', '--daemon-backlog', type='int', default=100,
        metavar='NUMBER', help='Depth of server socket listener '
        'backlog for daemon processes. Defaults to 100.')

add_option('unix', '--send-buffer-size', type='int', default=0,
        metavar='NUMBER', help='Size of socket buffer for sending '
        'data to daemon processes. Defaults to 0, indicating '
        'the system default socket buffer size is used.')

add_option('unix', '--receive-buffer-size', type='int', default=0,
        metavar='NUMBER', help='Size of socket buffer for receiving '
        'data from daemon processes. Defaults to 0, indicating '
        'the system default socket buffer size is used.')

add_option('unix', '--header-buffer-size', type='int', default=0,
        metavar='NUMBER', help='Size of buffer used for reading '
        'response headers from daemon processes. Defaults to 0, '
        'indicating internal default of 32768 bytes is used.')

add_option('unix', '--response-buffer-size', type='int', default=0,
        metavar='NUMBER', help='Maximum amount of response content '
        'that will be allowed to be buffered in the Apache child '
        'worker process when proxying the response from a daemon '
        'process. Defaults to 0, indicating internal default of '
        '65536 bytes is used.')

add_option('unix', '--response-socket-timeout', type='int', default=0,
        metavar='SECONDS', help='Maximum number of seconds allowed '
        'to pass before timing out on a write operation back to the '
        'HTTP client when the response buffer has filled and data is '
        'being forcibly flushed. Defaults to 0 seconds indicating that '
        'it will default to the value of the \'socket-timeout\' option.')

add_option('all', '--enable-sendfile', action='store_true',
        default=False, help='Flag indicating whether sendfile() support '
        'should be enabled. Defaults to being disabled. This should '
        'only be enabled if the operating system kernel and file system '
        'type where files are hosted supports it.')

add_option('unix', '--disable-reloading', action='store_true',
        default=False, help='Disables all reloading of daemon processes '
        'due to changes to the file containing the WSGI application '
        'entrypoint, or any other loaded source files. This has no '
        'effect when embedded mode is used as reloading is automatically '
        'disabled for embedded mode.')

add_option('unix', '--reload-on-changes', action='store_true',
        default=False, help='Flag indicating whether worker processes '
        'should be automatically restarted when any Python code file '
        'loaded by the WSGI application has been modified. Defaults to '
        'being disabled. When reloading on any code changes is disabled, '
        'unless all reloading is also disabled, the worker processes '
        'will still though be reloaded if the file containing the WSGI '
        'application entrypoint is modified.')

add_option('unix', '--user', default=default_run_user(),
        metavar='USERNAME', help='When being run by the root user, '
        'the user that the WSGI application should be run as.')

add_option('unix', '--group', default=default_run_group(),
        metavar='GROUP', help='When being run by the root user, the '
        'group that the WSGI application should be run as.')

add_option('all', '--callable-object', default='application',
        metavar='NAME', help='The name of the entry point for the WSGI '
        'application within the WSGI script file. Defaults to '
        'the name \'application\'.')

add_option('all', '--map-head-to-get', default='Auto',
        metavar='OFF|ON|AUTO', help='Flag indicating whether HEAD '
        'requests should be mapped to a GET request. By default a HEAD '
        'request will be automatically mapped to a GET request when an '
        'Apache output filter is detected that may want to see the '
        'entire response in order to set up response headers correctly '
        'for a HEAD request. This can be disable by setting to \'Off\'.')

add_option('all', '--document-root', metavar='DIRECTORY-PATH',
        help='The directory which should be used as the document root '
        'and which contains any static files.')

add_option('all', '--directory-index', metavar='FILE-NAME',
        help='The name of a directory index resource to be found in the '
        'document root directory. Requests mapping to the directory '
        'will be mapped to this resource rather than being passed '
        'through to the WSGI application.')

add_option('all', '--directory-listing', action='store_true',
        default=False, help='Flag indicating if directory listing '
        'should be enabled where static file application type is '
        'being used and no directory index file has been specified.')

add_option('all', '--allow-override', metavar='DIRECTIVE-TYPE',
        action='append', help='Allow directives to be overridden from a '
        '\'.htaccess\' file. Defaults to \'None\', indicating that any '
        '\'.htaccess\' file will be ignored with override directives '
        'not being permitted.')

add_option('all', '--mount-point', metavar='URL-PATH', default='/',
        help='The URL path at which the WSGI application will be '
        'mounted. Defaults to being mounted at the root URL of the '
        'site.')

add_option('all', '--url-alias', action='append', nargs=2,
        dest='url_aliases', metavar='URL-PATH FILE-PATH|DIRECTORY-PATH',
        help='Map a single static file or a directory of static files '
        'to a sub URL.')

add_option('all', '--error-document', action='append', nargs=2,
        dest='error_documents', metavar='STATUS URL-PATH', help='Map '
        'a specific sub URL as the handler for HTTP errors generated '
        'by the web server.')

add_option('all', '--error-override', action='store_true',
        default=False, help='Flag indicating whether Apache error '
        'documents will override application error responses.')

add_option('all', '--proxy-mount-point', action='append', nargs=2,
        dest='proxy_mount_points', metavar='URL-PATH URL',
        help='Map a sub URL such that any requests against it will be '
        'proxied to the specified URL. This is only for proxying to a '
        'site as a whole, or a sub site, not individual resources.')

add_option('all', '--proxy-url-alias', action='append', nargs=2,
        dest='proxy_mount_points', metavar='URL-PATH URL',
        help=optparse.SUPPRESS_HELP)

add_option('all', '--proxy-virtual-host', action='append', nargs=2,
        dest='proxy_virtual_hosts', metavar='HOSTNAME URL',
        help='Proxy any requests for the specified host name to the '
        'remote URL.')

add_option('all', '--trust-proxy-header', action='append', default=[],
        dest='trusted_proxy_headers', metavar='HEADER-NAME',
        help='The name of any trusted HTTP header providing details '
        'of the front end client request when proxying.')

add_option('all', '--trust-proxy', action='append', default=[],
        dest='trusted_proxies', metavar='IP-ADDRESS/SUBNET',
        help='The IP address or subnet corresponding to any trusted '
        'proxy.')

add_option('all', '--keep-alive-timeout', type='int', default=2,
        metavar='SECONDS', help='The number of seconds which a client '
        'connection will be kept alive to allow subsequent requests '
        'to be made over the same connection when a keep alive '
        'connection is requested. Defaults to 2, indicating that keep '
        'alive connections are set for 2 seconds.')

add_option('all', '--compress-responses', action='store_true',
        default=False, help='Flag indicating whether responses for '
        'common text based responses, such as plain text, HTML, XML, '
        'CSS and Javascript should be compressed.')

add_option('all', '--server-metrics', action='store_true',
        default=False, help='Flag indicating whether internal server '
        'metrics will be available within the WSGI application. '
        'Defaults to being disabled.')

add_option('all', '--telemetry-service', metavar='TARGET',
        default=None, help='Target metrics service to push telemetry to. '
        'Enables WSGITelemetryService in the generated config. Use '
        '"unix:/path/to/socket" for a local datagram socket (same-host '
        'ingester). Remote "udp:host:port" targets are not supported. '
        'Off by default.')

add_option('unix', '--enable-telemetry', action='store_true', default=False,
        help='Bundle a telemetry ingester and web UI alongside the WSGI '
        'application. Generates a service-script daemon that runs the '
        'mod_wsgi-telemetry ingester on a UNIX socket inside the server '
        'root and emits WSGITelemetryService pointing at that socket so '
        'the WSGI processes report to it. Requires the mod_wsgi-telemetry '
        'package to be installed. Mutually exclusive with '
        '--telemetry-service.')

add_option('unix', '--telemetry-ui-port', type='int', default=8888,
        metavar='NUMBER', help='HTTP port the telemetry web UI binds to '
        'on 127.0.0.1 when --enable-telemetry is set. Defaults to '
        '%default. Two express instances on the same host need distinct '
        'ports to avoid a bind collision.')

add_option('all', '--telemetry-interval', type='float', default=1.0,
        metavar='SECONDS', help='Metrics reporter sampling interval '
        'in seconds. Only applies when --telemetry-service or '
        '--enable-telemetry is set. Defaults to %default.')

add_option('all', '--slow-requests', type='float', default=None,
        metavar='SECONDS', help='Enable slow-request reporting and set '
        'the threshold in seconds above which a still-running request '
        'is reported. Generates WSGISlowRequests in the config. Only '
        'meaningful alongside --telemetry-service. Off by default.')

add_option('all', '--switch-interval', type='float', default=None,
        metavar='SECONDS', help='Override the Python GIL switch interval '
        '(sys.setswitchinterval). Applied at process start in both '
        'embedded and daemon mode via WSGISwitchInterval and the '
        'switch-interval option on WSGIDaemonProcess. Defaults to '
        'Python\'s built-in 0.005 (5 ms) when unset.')

add_option('all', '--free-threading', action='store_true', default=False,
        help='Emit WSGIFreeThreading On in the generated configuration to '
        'run the Python interpreter without the GIL. Requires a Python '
        'build with free-threading support (PEP 703, --disable-gil); '
        'mod_wsgi-express will exit with an error if the running Python '
        'does not support it.')

add_option('all', '--telemetry-options', action='append', default=[],
        metavar='ARGS', help='Apache-Options-style metrics-capture '
        'toggle, passed verbatim to a WSGITelemetryOptions directive in '
        'the generated config. Each occurrence of this flag emits a '
        'separate directive, so the +/- / absolute / None / All forms '
        'compose just as they do when written by hand. Example: '
        '--telemetry-options "+CaptureUserAgent". Repeatable.')

add_option('all', '--server-status', action='store_true',
        default=False, help='Flag indicating whether web server status '
        'will be available at the /server-status sub URL. Defaults to '
        'being disabled.')

add_option('all', '--host-access-script', metavar='SCRIPT-PATH',
        default=None, help='Specify a Python script file for '
        'performing host access checks.')

add_option('all', '--auth-user-script', metavar='SCRIPT-PATH',
        default=None, help='Specify a Python script file for '
        'performing user authentication.')

add_option('all', '--auth-type', metavar='TYPE',
        default='Basic', help='Specify the type of authentication '
        'scheme used when authenticating users. Defaults to using '
        '\'Basic\'. Alternate schemes available are \'Digest\'.')

add_option('all', '--auth-group-script', metavar='SCRIPT-PATH',
        default=None, help='Specify a Python script file for '
        'performing group based authorization in conjunction with '
        'a user authentication script.')

add_option('all', '--auth-group', metavar='NAME',
        default='wsgi', help='Specify the group which users should '
        'be a member of when using a group based authorization script. '
        'Defaults to \'wsgi\' as a place holder but should be '
        'overridden to be the actual group you use rather than '
        'making your group name match the default.')

add_option('all', '--include-file', action='append',
        dest='include_files', metavar='FILE-PATH', help='Specify the '
        'path to an additional web server configuration file to be '
        'included at the end of the generated web server configuration '
        'file.')

add_option('all', '--rewrite-rules', metavar='FILE-PATH',
        help='Specify an alternate server configuration file which '
        'contains rewrite rules. Defaults to using the '
        '\'rewrite.conf\' stored under the server root directory.')

add_option('unix', '--envvars-script', metavar='FILE-PATH',
        help='Specify an alternate script file for user defined web '
        'server environment variables. Defaults to using the '
        '\'envvars\' stored under the server root directory.')

add_option('unix', '--lang', default=None, metavar='NAME',
        help=optparse.SUPPRESS_HELP)

add_option('all', '--locale', default=None, metavar='NAME',
        help='Specify the natural language locale for the process '
        'as normally defined by the \'LC_ALL\' environment variable. '
        'If not specified, then the default locale for this process '
        'will be used. If the default locale is however \'C\' or '
        '\'POSIX\' then an attempt will be made to use either the '
        '\'en_US.UTF-8\' or \'C.UTF-8\' locales and if that is not '
        'possible only then fallback to the default locale of this '
        'process.')

add_option('all', '--setenv', action='append', nargs=2,
        dest='setenv_variables', metavar='KEY VALUE', help='Specify '
        'a name/value pairs to be added to the per request WSGI environ '
        'dictionary')

add_option('all', '--passenv', action='append',
        dest='passenv_variables', metavar='KEY', help='Specify the '
        'names of any process level environment variables which should '
        'be passed as a name/value pair in the per request WSGI '
        'environ dictionary.')

add_option('all', '--working-directory', metavar='DIRECTORY-PATH',
        help='Specify the directory which should be used as the '
        'current working directory of the WSGI application. This '
        'directory will be searched when importing Python modules '
        'so long as the WSGI application doesn\'t subsequently '
        'change the current working directory. Defaults to the '
        'directory this script is run from.')

add_option('all', '--pid-file', metavar='FILE-PATH',
        help='Specify an alternate file to be used to store the '
        'process ID for the root process of the web server.')

add_option('all', '--server-root', metavar='DIRECTORY-PATH',
        help='Specify an alternate directory for where the generated '
        'web server configuration, startup files and logs will be '
        'stored. On Linux defaults to the sub directory specified by '
        'the TMPDIR environment variable, or /tmp if not specified. '
        'On macOS, defaults to the /var/tmp directory.')

add_option('unix', '--server-mpm', action='append',
        dest='server_mpm_variables', metavar='NAME', help='Specify '
        'preferred MPM to use when using Apache 2.4 with dynamically '
        'loadable MPMs and more than one is available. By default '
        'the MPM precedence order when no preference is given is '
        '\"event\", \"worker" and \"prefork\".')

add_option('all', '--log-directory', metavar='DIRECTORY-PATH',
        help='Specify an alternate directory for where the log files '
        'will be stored. Defaults to the server root directory.')

add_option('all', '--log-level', default='warn', metavar='NAME',
        help='Specify the log level for logging. Defaults to \'warn\'.')

add_option('all', '--access-log', action='store_true', default=False,
        help='Flag indicating whether the web server access log '
        'should be enabled. Defaults to being disabled.')

add_option('unix', '--startup-log', action='store_true', default=False,
        help='Flag indicating whether the web server startup log should '
        'be enabled. Defaults to being disabled.')

add_option('all', '--verbose-debugging', action='store_true',
        dest='verbose_debugging', help=optparse.SUPPRESS_HELP)

add_option('unix', '--log-to-terminal', action='store_true',
        default=False, help='Flag indicating whether logs should '
        'be directed back to the terminal. Defaults to being disabled. '
        'If --log-directory is set explicitly, it will override this '
        'option. If logging to the terminal is carried out, any '
        'rotating of log files will be disabled.')

add_option('all', '--access-log-format', metavar='FORMAT',
        help='Specify the format of the access log records.'),

add_option('all', '--error-log-format', metavar='FORMAT',
        help='Specify the format of the error log records.'),

add_option('all', '--error-log-name', metavar='FILE-NAME',
        default='error_log', help='Specify the name of the error '
        'log file when it is being written to the log directory.'),

add_option('all', '--access-log-name', metavar='FILE-NAME',
        default='access_log', help='Specify the name of the access '
        'log file when it is being written to the log directory.'),

add_option('unix', '--startup-log-name', metavar='FILE-NAME',
        default='startup_log', help='Specify the name of the startup '
        'log file when it is being written to the log directory.'),

add_option('unix', '--rotate-logs', action='store_true', default=False,
        help='Flag indicating whether log rotation should be performed.'),

add_option('unix', '--max-log-size', default=5, type='int',
        metavar='MB', help='The maximum size in MB the log file should '
        'be allowed to reach before log file rotation is performed.'),

add_option('unix', '--rotatelogs-executable',
        default=apxs_config.ROTATELOGS, metavar='FILE-PATH',
        help='Override the path to the rotatelogs executable.'),

add_option('all', '--python-path', action='append',
        dest='python_paths', metavar='DIRECTORY-PATH', help='Specify '
        'the path to any additional directory that should be added to '
        'the Python module search path. Note that these directories will '
        'not be processed for \'.pth\' files. If processing of \'.pth\' '
        'files is required, set the \'PYTHONPATH\' environment variable '
        'in a script specified by the \'--envvars-script\' option.')

add_option('all', '--python-eggs', metavar='DIRECTORY-PATH',
        help='Specify an alternate directory which should be used for '
        'unpacking of Python eggs. Defaults to a sub directory of '
        'the server root directory.')

add_option('unix', '--shell-executable', default=SHELL,
        metavar='FILE-PATH', help='Override the path to the shell '
        'used in the \'apachectl\' script. The \'bash\' shell will '
        'be used if available.')

add_option('unix', '--httpd-executable', default=apxs_config.HTTPD,
        metavar='FILE-PATH', help='Override the path to the Apache web '
        'server executable.')

add_option('unix', '--process-name', metavar='NAME', help='Override '
        'the name given to the Apache parent process. This might be '
        'needed when a process manager expects the process to be named '
        'a certain way but due to a sequence of exec calls the name '
        'changed.')

add_option('all', '--modules-directory', default=apxs_config.LIBEXECDIR,
        metavar='DIRECTORY-PATH', help='Override the path to the Apache '
        'web server modules directory.')

add_option('unix', '--mime-types', default=find_mimetypes(),
        metavar='FILE-PATH', help='Override the path to the mime types '
        'file used by the web server.')

add_option('unix', '--socket-prefix', metavar='DIRECTORY-PATH',
        help='Specify an alternate directory name prefix to be used '
        'for the UNIX domain sockets used by mod_wsgi to communicate '
        'between the Apache child processes and the daemon processes.')

add_option('all', '--add-handler', action='append', nargs=2,
        dest='handler_scripts', metavar='EXTENSION SCRIPT-PATH',
        help='Specify a WSGI application to be used as a special '
        'handler for any resources matched from the document root '
        'directory with a specific extension type.')

add_option('all', '--chunked-request', action='store_true',
        default=False, help='Flag indicating whether requests which '
        'use chunked transfer encoding will be accepted.')

add_option('hidden', '--with-php5', action='store_true', default=False,
        help='Flag indicating whether PHP 5 support should be enabled. '
        'PHP code files must use the \'.php\' extension.')

add_option('all', '--with-cgi', action='store_true', default=False,
        help='Flag indicating whether CGI script support should be '
        'enabled. CGI scripts must use the \'.cgi\' extension and be '
        'executable')

add_option('unix', '--service-script', action='append', nargs=2,
        dest='service_scripts', metavar='SERVICE SCRIPT-PATH',
        help='Specify the name of a Python script to be loaded and '
        'executed in the context of a distinct daemon process. Used '
        'for running a managed service.')

add_option('unix', '--service-user', action='append', nargs=2,
        dest='service_users', metavar='SERVICE USERNAME',
        help='When being run by the root user, the user that the '
        'distinct daemon process started to run the managed service '
        'should be run as.')

add_option('unix', '--service-group', action='append', nargs=2,
        dest='service_groups', metavar='SERVICE GROUP',
        help='When being run by the root user, the group that the '
        'distinct daemon process started to run the managed service '
        'should be run as.')

add_option('unix', '--service-log-file', action='append', nargs=2,
        dest='service_log_files', metavar='SERVICE FILE-NAME',
        help='Specify the name of a separate log file to be used for '
        'the managed service.')

add_option('all', '--orphan-interpreter', action='store_true',
        default=False, help='Flag indicating whether should skip over '
        'destroying the Python interpreter on process shutdown.')

add_option('unix', '--embedded-mode', action='store_true', default=False,
        help='Flag indicating whether to run in embedded mode rather '
        'than the default daemon mode. Numerous daemon mode specific '
        'features will not operate when this mode is used.')

add_option('all', '--enable-docs', action='store_true', default=False,
        help='Flag indicating whether the mod_wsgi documentation should '
        'be made available at the /__wsgi__/docs sub URL.')

add_option('unix', '--debug-mode', action='store_true', default=False,
        help='Flag indicating whether to run in single process mode '
        'to allow the running of an interactive Python debugger. This '
        'will override all options related to processes, threads and '
        'communication with workers. All forms of source code reloading '
        'will also be disabled. Both stdin and stdout will be attached '
        'to the console to allow interaction with the Python debugger.')

add_option('unix', '--enable-debugger', action='store_true',
        default=False, help='Flag indicating whether post mortem '
        'debugging of any exceptions which propagate out from the '
        'WSGI application when running in debug mode should be '
        'performed. Post mortem debugging is performed using the '
        'Python debugger (pdb).'),

add_option('unix', '--debugger-startup', action='store_true',
        default=False, help='Flag indicating whether when post '
        'mortem debugging is enabled, that the debugger should '
        'also be thrown into the interactive console on initial '
        'startup of the server to allow breakpoints to be setup.'),

add_option('unix', '--enable-coverage', action='store_true',
        default=False, help='Flag indicating whether coverage analysis '
        'is enabled when running in debug mode.')

add_option('unix', '--coverage-directory', metavar='DIRECTORY-PATH',
        default='', help='Override the path to the directory into '
        'which coverage analysis will be generated when enabled under '
        'debug mode.')

add_option('unix', '--enable-profiler', action='store_true',
        default=False, help='Flag indicating whether code profiling '
        'is enabled when running in debug mode.')

add_option('unix', '--profiler-directory', metavar='DIRECTORY-PATH',
        default='', help='Override the path to the directory into '
        'which profiler data will be written when enabled under debug '
        'mode.')

add_option('unix', '--enable-recorder', action='store_true',
        default=False, help='Flag indicating whether recording of '
        'requests is enabled when running in debug mode.')

add_option('unix', '--recorder-directory', metavar='DIRECTORY-PATH',
        default='', help='Override the path to the directory into '
        'which recorder data will be written when enabled under debug '
        'mode.')

add_option('unix', '--enable-gdb', action='store_true',
        default=False, help='Flag indicating whether Apache should '
        'be run under \'gdb\' when running in debug mode. This '
        'would be use to debug process crashes.')

add_option('unix', '--gdb-executable', default='gdb',
        metavar='FILE-PATH', help='Override the path to the gdb '
        'executable.')

add_option('unix', '--setup-only', action='store_true', default=False,
        help='Flag indicating that after the configuration files have '
        'been setup, that the command should then exit and not go on '
        'to actually run up the Apache server. This is to allow for '
        'the generation of the configuration with Apache then later '
        'being started separately using the generated \'apachectl\' '
        'script.')

# add_option('unix', '--isatty', action='store_true', default=False,
#         help='Flag indicating whether should assume being run in an '
#         'interactive terminal session. In this case Apache will not '
#         'replace this wrapper script, but will be run as a sub process.'
#         'Signals such as SIGINT, SIGTERM, SIGHUP and SIGUSR1 will be '
#         'forwarded onto Apache, but SIGWINCH will be blocked so that '
#         'resizing of a terminal session window will not cause Apache '
#         'to shutdown. This is a separate option at this time rather '
#         'than being determined automatically while the reliability of '
#         'intercepting and forwarding signals is verified.')
