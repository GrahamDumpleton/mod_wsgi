import os
import logging

try:
    from ConfigParser import RawConfigParser, NoOptionError
except ImportError:
    from configparser import RawConfigParser, NoOptionError

from .interface import Interface
from .sampler import Sampler

import apache

LOG_LEVEL = {
    'CRITICAL': logging.CRITICAL,
    'ERROR': logging.ERROR,
    'WARNING': logging.WARNING,
    'INFO': logging.INFO,
    'DEBUG': logging.DEBUG,
}

LOG_FORMAT = '%(asctime)s (%(process)d/%(threadName)s) ' \
              '%(name)s %(levelname)s - %(message)s'

def start(name):
    if apache.scoreboard() is None:
        return

    config_object = RawConfigParser()

    config_file = os.environ.get('NEW_RELIC_CONFIG_FILE')

    if config_file:
        config_object.read([config_file])

    def option(name, section='newrelic', type=None, **kwargs):
        try:
            getter = 'get%s' % (type or '')
            return getattr(config_object, getter)(section, name)
        except NoOptionError:
            if 'default' in kwargs:
                return kwargs['default']
            else:
                raise

    log_level = os.environ.get('NEW_RELIC_LOG_LEVEL', 'INFO').upper()
    log_level = option('log_level', default=log_level).upper()

    if log_level in LOG_LEVEL:
        log_level = LOG_LEVEL[log_level]
    else:
        log_level = logging.INFO

    logging.basicConfig(level=log_level, format=LOG_FORMAT)

    license_key = os.environ.get('NEW_RELIC_LICENSE_KEY')
    license_key = option('license_key', default=license_key)

    interface = Interface(license_key)
    sampler = Sampler(interface, name)

    sampler.start()
