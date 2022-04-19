import os
import sys
import inspect
import signal
import subprocess

from django.core.management.base import BaseCommand

import mod_wsgi.server

def check_percentage(string):
    if value is not None and value < 0 or value > 1:
        import argparse
        msg = '%s option value needs to be within the range 0 to 1.' % string
        raise argparse.ArgumentTypeError(msg)
    return value

class Command(BaseCommand):

    args = ''
    help = 'Starts Apache/mod_wsgi web server.'

    if hasattr(BaseCommand, 'option_list'):
        # Used prior to Django 1.10.

        option_list = BaseCommand.option_list + mod_wsgi.server.option_list

    else:
        # This horrible mess tries to convert optparse option list to
        # argparse as required by Django 1.10+. We can't switch to
        # using argparse as need to still support Python 2.6, which
        # lacks the argparse module.

        def add_arguments(self, parser):
            ignore = set(['const', 'callback', 'callback_args',
                          'callback_kwargs'])
            types = { 'int': int, 'string': str }

            for option in mod_wsgi.server.option_list:
                opts = option._short_opts + option._long_opts
                kwargs = {}

                for attr in option.ATTRS:
                    if attr not in ignore and hasattr(option, attr):
                        if attr == 'type':
                            if getattr(option, attr) in types:
                                kwargs[attr] = types[getattr(option, attr)]
                        elif attr == 'default':
                            if getattr(option, attr) != ('NO', 'DEFAULT'):
                                kwargs[attr] = getattr(option, attr)
                        else:
                            if getattr(option, attr) is not None:
                                kwargs[attr] = getattr(option, attr)

                    if (kwargs.get('action') == 'callback' and
                            option.callback.__name__ == 'check_percentage'):
                        del kwargs['action']
                        kwargs['type'] = check_percentage

                    if kwargs.get('nargs') == 1:
                        del kwargs['nargs']

                parser.add_argument(*opts, **kwargs)

    def handle(self, *args, **options):
        self.stdout.write('Successfully ran command.')

        from django.conf import settings
        wsgi_application = settings.WSGI_APPLICATION

        fields = wsgi_application.split('.')

        module_name = '.'.join(fields[:-1])
        callable_object = fields[-1]

        # XXX Can't test import as loading the WSGI module may have
        # side effects and run things that should only be run inside
        # of the mod_wsgi process.
        #
        #     __import__(module_name)

        options['application_type'] = 'module'
        options['callable_object'] = callable_object

        args = [module_name]

        # If there is no BASE_DIR in Django settings, assume that the
        # current working directory is the parent directory of the
        # directory the settings module is in. Either way, allow the
        # --working-directory option to override it to deal with where
        # meaning of BASE_DIR in the Django settings was changed.

        if options.get('working_directory') is None:
            if hasattr(settings, 'BASE_DIR'):
                options['working_directory'] = settings.BASE_DIR
            else:
                settings_module_path = os.environ['DJANGO_SETTINGS_MODULE']
                root_module_path = settings_module_path.split('.')[0]
                root_module = sys.modules[root_module_path]
                parent = os.path.dirname(os.path.dirname(root_module.__file__))
                options['working_directory'] = parent

        url_aliases = options.setdefault('url_aliases') or []

        try:
            middleware = getattr(settings, 'MIDDLEWARE', None)

            if middleware is None:
                middleware = getattr(settings, 'MIDDLEWARE_CLASSES', [])

            if 'whitenoise.middleware.WhiteNoiseMiddleware' not in middleware: 
                if settings.STATIC_URL and settings.STATIC_URL.startswith('/'):
                    if settings.STATIC_ROOT:
                        # We need a fiddle here as depending on the Python
                        # version used, the list of URL aliases we are
                        # passed could be either list of tuples or list of
                        # lists. We need to ensure we use the same type so
                        # that sorting of items in the lists works later.

                        if not url_aliases:
                            url_aliases.insert(0, (
                                    settings.STATIC_URL.rstrip('/') or '/',
                                    settings.STATIC_ROOT))
                        else:
                            url_aliases.insert(0, type(url_aliases[0])((
                                    settings.STATIC_URL.rstrip('/') or '/',
                                    settings.STATIC_ROOT)))

        except AttributeError:
            pass

        options['url_aliases'] = url_aliases

        options = mod_wsgi.server._cmd_setup_server(
                'start-server', args, options)

        if options['setup_only']:
            return

        executable = os.path.join(options['server_root'], 'apachectl')
        name = executable.ljust(len(options['process_name']))

        if sys.stdout.isatty() and not options['debug_mode']:
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
            os.execl(executable, name, 'start', '-DFOREGROUND')
