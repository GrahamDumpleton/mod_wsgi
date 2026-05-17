import getpass
import inspect
import locale
import math
import os
import posixpath
import sys
import sysconfig
import tempfile

from . import apxs_config
from .platform import find_program, MOD_WSGI_SO, PYTHON_DYLIB
from .apache import generate_apache_config
from .scripts import generate_wsgi_handler_script, generate_control_scripts

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

def setup_server(command, args, options):
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

    if options['telemetry_service']:
        target = options['telemetry_service']
        if not target.startswith('unix:'):
            raise ConfigurationError(
                "--telemetry-service must be 'unix:/path' "
                "(remote 'udp:host:port' targets are no longer supported)")
    else:
        options['telemetry_service'] = ''

    if options['slow_requests'] is not None:
        if options['slow_requests'] < 0:
            raise ConfigurationError(
                "--slow-requests threshold must be non-negative")
        if not options['telemetry_service']:
            raise ConfigurationError(
                "--slow-requests requires --telemetry-service")
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

    if options['free_threading']:
        if not sysconfig.get_config_var('Py_GIL_DISABLED'):
            raise ConfigurationError(
                "--free-threading requires a Python build with "
                "free-threading support (PEP 703). Rebuild Python "
                "with --disable-gil to use it.")

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
    if options['telemetry_service']:
        options['httpd_arguments_list'].append('-DMOD_WSGI_TELEMETRY_SERVICE')
    if options['slow_requests'] != '':
        options['httpd_arguments_list'].append('-DMOD_WSGI_SLOW_REQUESTS')
    if options['switch_interval'] != '':
        options['httpd_arguments_list'].append('-DMOD_WSGI_SWITCH_INTERVAL')
    if options['free_threading']:
        options['httpd_arguments_list'].append('-DMOD_WSGI_FREE_THREADING')
    if options['telemetry_options']:
        options['httpd_arguments_list'].append('-DMOD_WSGI_TELEMETRY_OPTIONS')
        options['telemetry_options'] = '\n'.join(
            'WSGITelemetryOptions %s' % v for v in options['telemetry_options'])
    else:
        options['telemetry_options'] = ''
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

