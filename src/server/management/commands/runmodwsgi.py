import os
import sys
import inspect

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

        __import__(module_name)

        script_file = inspect.getsourcefile(sys.modules[module_name])

        args = [script_file]
        options['callable_object'] = callable_object

        # If there is no BASE_DIR in Django settings, assume that
        # the current working directory is the parent directory of
        # the directory the settings module is in.

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
            if settings.STATIC_URL and settings.STATIC_URL.startswith('/'):
                if settings.STATIC_ROOT:
                    url_aliases.insert(0,
                            (settings.STATIC_URL.rstrip('/') or '/',
                            settings.STATIC_ROOT))
        except AttributeError:
            pass

        options['url_aliases'] = url_aliases

        options = mod_wsgi.server._cmd_setup_server(
                'start-server', args, options)

        if options['setup_only']:
            return

        executable = os.path.join(options['server_root'], 'apachectl')
        name = executable.ljust(len(options['process_name']))
        os.execl(executable, name, 'start', '-DFOREGROUND')
