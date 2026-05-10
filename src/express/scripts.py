import os

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
