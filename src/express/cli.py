import copy
import optparse
import os
import posixpath
import shutil
import signal
import subprocess
import sys
import sysconfig

from . import apxs_config
from .platform import MOD_WSGI_SO, PYTHON_DYLIB
from .options import option_list
from .server import setup_server, ConfigurationError

def cmd_setup_server(params):
    formatter = optparse.IndentedHelpFormatter()
    formatter.set_long_opt_delimiter(' ')

    usage = '%prog setup-server script [options]'
    parser = optparse.OptionParser(usage=usage, option_list=option_list,
            formatter=formatter)

    (options, args) = parser.parse_args(params)

    try:
        setup_server('setup-server', args, vars(options))
    except ConfigurationError as exc:
        parser.error(str(exc))

def cmd_start_server(params):
    formatter = optparse.IndentedHelpFormatter()
    formatter.set_long_opt_delimiter(' ')

    usage = '%prog start-server script [options]'
    parser = optparse.OptionParser(usage=usage, option_list=option_list,
            formatter=formatter)

    (options, args) = parser.parse_args(params)

    try:
        config = setup_server('start-server', args, vars(options))
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

        # On Windows httpd shares our console, so a Ctrl-C delivers a
        # CTRL_C_EVENT to the whole console process group and httpd runs
        # its own graceful shutdown. We must not let the same Ctrl-C kill
        # this launcher first, or it returns to the shell while httpd is
        # still tearing down (and dumps a KeyboardInterrupt traceback). So
        # absorb our own interrupt and keep waiting until httpd exits.
        #
        # A first Ctrl-C is treated as "you should have received the
        # console event, shutting down gracefully, I will wait". If httpd
        # did not actually receive the event (for example a git-bash pty
        # bridge that does not forward it to the child), a second Ctrl-C
        # escalates to terminating it so we cannot hang indefinitely.

        process = subprocess.Popen([executable]+httpd_arguments, env=environ)

        interrupts = 0

        while True:
            try:
                process.wait()
                break
            except KeyboardInterrupt:
                interrupts += 1
                if interrupts >= 2:
                    process.terminate()

        sys.exit(process.returncode)

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
