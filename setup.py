from __future__ import print_function

import os
import sys
import fnmatch
import subprocess
import re

from setuptools import setup
from distutils.core import Extension
from distutils.sysconfig import get_config_var as get_python_config
from distutils.sysconfig import get_python_lib

# Compile all available source files.

source_files = [os.path.join('src/server', name) for name in 
        os.listdir(os.path.join(os.path.dirname(os.path.abspath(__file__)),
        'src/server')) if fnmatch.fnmatch(name, '*.c')]

# Work out all the Apache specific compilation flags.

def find_program(names, default=None, paths=[]):
    for name in names:
        for path in os.environ['PATH'].split(':') + paths:
            program = os.path.join(path, name)
            if os.path.exists(program):
                return program
    return default

APXS = os.environ.get('APXS')

if APXS is None:
    APXS = find_program(['apxs2', 'apxs'], 'apxs', ['/usr/sbin', os.getcwd()])
elif not os.path.isabs(APXS):
    APXS = find_program([APXS], APXS, ['/usr/sbin', os.getcwd()])

if not os.path.isabs(APXS) or not os.access(APXS, os.X_OK):
    raise RuntimeError('The %r command appears not to be installed or is '
            'not executable. Please check the list of prerequisites in the '
            'documentation for this package and install any missing '
            'Apache httpd server packages.' % APXS)

def get_apxs_config(query):
    p = subprocess.Popen([APXS, '-q', query],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = p.communicate()
    if isinstance(out, bytes):
        out = out.decode('UTF-8')
    return out.strip()

INCLUDEDIR = get_apxs_config('INCLUDEDIR')
CPPFLAGS = get_apxs_config('CPPFLAGS').split()
CFLAGS = get_apxs_config('CFLAGS').split()

EXTRA_INCLUDES = get_apxs_config('EXTRA_INCLUDES').split()
EXTRA_CPPFLAGS = get_apxs_config('EXTRA_CPPFLAGS').split()
EXTRA_CFLAGS = get_apxs_config('EXTRA_CFLAGS').split()

# Write out apxs_config.py which caches various configuration
# related to Apache.

BINDIR = get_apxs_config('BINDIR')
SBINDIR = get_apxs_config('SBINDIR')

PROGNAME = get_apxs_config('PROGNAME')

MPM_NAME = get_apxs_config('MPM_NAME')
LIBEXECDIR = get_apxs_config('LIBEXECDIR')
SHLIBPATH_VAR = get_apxs_config('SHLIBPATH_VAR')

if os.path.exists(os.path.join(SBINDIR, PROGNAME)):
    HTTPD = os.path.join(SBINDIR, PROGNAME)
elif os.path.exists(os.path.join(BINDIR, PROGNAME)):
    HTTPD = os.path.join(BINDIR, PROGNAME)
else:
    HTTPD = PROGNAME

with open(os.path.join(os.path.dirname(__file__),
        'src/server/apxs_config.py'), 'w') as fp:
    print('HTTPD = "%s"' % HTTPD, file=fp)
    print('BINDIR = "%s"' % BINDIR, file=fp)
    print('SBINDIR = "%s"' % SBINDIR, file=fp)
    print('PROGNAME = "%s"' % PROGNAME, file=fp)
    print('MPM_NAME = "%s"' % MPM_NAME, file=fp)
    print('LIBEXECDIR = "%s"' % LIBEXECDIR, file=fp)
    print('SHLIBPATH_VAR = "%s"' % SHLIBPATH_VAR, file=fp)

# Work out location of Python library and how to link it.

PYTHON_VERSION = get_python_config('VERSION')
PYTHON_LDVERSION = get_python_config('LDVERSION') or PYTHON_VERSION

PYTHON_LIBDIR = get_python_config('LIBDIR')
PYTHON_CFGDIR =  get_python_lib(plat_specific=1, standard_lib=1) + '/config'

if PYTHON_LDVERSION and PYTHON_LDVERSION != PYTHON_VERSION:
    PYTHON_CFGDIR = '%s-%s' % (PYTHON_CFGDIR, PYTHON_LDVERSION)

PYTHON_LDFLAGS = ['-L%s' % PYTHON_LIBDIR, '-L%s' % PYTHON_CFGDIR]
PYTHON_LDLIBS = ['-lpython%s' % PYTHON_LDVERSION]

if os.path.exists(os.path.join(PYTHON_LIBDIR,
        'libpython%s.a' % PYTHON_VERSION)):
    PYTHON_LDLIBS = ['-lpython%s' % PYTHON_VERSION]

if os.path.exists(os.path.join(PYTHON_CFGDIR,
        'libpython%s.a' % PYTHON_VERSION)):
    PYTHON_LDLIBS = ['-lpython%s' % PYTHON_VERSION]

# Create the final set of compilation flags to be used.

INCLUDE_DIRS = [INCLUDEDIR]
EXTRA_COMPILE_FLAGS = (EXTRA_INCLUDES + CPPFLAGS + EXTRA_CPPFLAGS +
        CFLAGS + EXTRA_CFLAGS)
EXTRA_LINK_ARGS = PYTHON_LDFLAGS + PYTHON_LDLIBS

# Force adding of LD_RUN_PATH for platforms that may need it.

LD_RUN_PATH = os.environ.get('LD_RUN_PATH', '')
LD_RUN_PATH += ':%s:%s' % (PYTHON_LIBDIR, PYTHON_CFGDIR)
LD_RUN_PATH = LD_RUN_PATH.lstrip(':')

os.environ['LD_RUN_PATH'] = LD_RUN_PATH

# If using Python 3.4, then minimum MacOS X version you can use is 10.8.
# We have to force this with the compiler otherwise Python 3.4 sets it
# to 10.6 which screws up Apache APR % formats for apr_time_t, which
# breaks daemon mode queue time.

if sys.version_info >= (3, 4):
    os.environ['MACOSX_DEPLOYMENT_TARGET'] = '10.8'

# Now add the definitions to build everything.

extension_name = 'mod_wsgi.server.mod_wsgi-py%s%s' % sys.version_info[:2]

extension = Extension(extension_name, source_files,
        include_dirs=INCLUDE_DIRS, extra_compile_args=EXTRA_COMPILE_FLAGS,
        extra_link_args=EXTRA_LINK_ARGS)

def _documentation():
    result = []
    prefix = 'docs/_build/html'
    for root, dirs, files in os.walk(prefix, topdown=False):
        for name in files:
            if root == prefix:
                result.append(os.path.join(root[len(prefix):], name))
            else:
                result.append(os.path.join(root[len(prefix)+1:], name))
    return result

def _version():
    path = 'src/server/wsgi_version.h'
    pattern = r'#define MOD_WSGI_VERSION_STRING "(?P<version>[^"]*)"'
    with open(path, 'r') as fp:
        match = re.search(pattern, fp.read(), flags=re.MULTILINE)
    return match.group('version')

setup(name = 'mod_wsgi',
    version = _version(),
    description = 'Installer for Apache/mod_wsgi.',
    author = 'Graham Dumpleton',
    author_email = 'Graham.Dumpleton@gmail.com',
    maintainer = 'Graham Dumpleton',
    maintainer_email = 'Graham.Dumpleton@gmail.com',
    url = 'http://www.modwsgi.org/',
    #bugtrack_url = 'https://github.com/GrahamDumpleton/mod_wsgi/issues',
    license = 'Apache License, Version 2.0',
    platforms = [],
    download_url = None,
    classifiers= [
        'Development Status :: 6 - Mature',
        'License :: OSI Approved :: Apache Software License',
        'Operating System :: MacOS :: MacOS X',
        'Operating System :: POSIX',
        'Operating System :: POSIX :: BSD',
        'Operating System :: POSIX :: Linux',
        'Operating System :: POSIX :: SunOS/Solaris',
        'Programming Language :: Python',
        'Programming Language :: Python :: Implementation :: CPython',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Topic :: Internet :: WWW/HTTP :: WSGI',
        'Topic :: Internet :: WWW/HTTP :: WSGI :: Server'
    ],
    packages = ['mod_wsgi', 'mod_wsgi.server', 'mod_wsgi.server.management',
        'mod_wsgi.server.management.commands', 'mod_wsgi.docs',
        'mod_wsgi.images'],
    package_dir = {'mod_wsgi': 'src', 'mod_wsgi.docs': 'docs/_build/html',
        'mod_wsgi.images': 'images'},
    package_data = {'mod_wsgi.docs': _documentation(),
        'mod_wsgi.images': ['snake-whiskey.jpg']},
    ext_modules = [extension],
    entry_points = { 'console_scripts':
        ['mod_wsgi-express = mod_wsgi.server:main'],},
    install_requires=['mod_wsgi-metrics >= 1.0.0'],
)
