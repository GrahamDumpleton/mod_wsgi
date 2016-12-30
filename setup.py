from __future__ import print_function

import os
import sys
import fnmatch
import subprocess
import tarfile
import shutil
import stat
import re

try:
    from urllib.request import urlretrieve
except ImportError:
    from urllib import urlretrieve

from setuptools import setup
from distutils.core import Extension
from distutils.sysconfig import get_config_var as get_python_config
from distutils.sysconfig import get_python_lib

# Before anything else, this setup.py uses some tricks to potentially
# install Apache. This can be from a local tarball, or from precompiled
# Apache binaries for Heroku and OpenShift environments downloaded from
# Amazon S3. Once they are installed, then the installation of the
# mod_wsgi package itself will be triggered, ensuring that it can be
# built against the precompiled Apache binaries which were installed.
#
# First work out whether we are actually running on either Heroku or
# OpenShift. If we are, then we identify the set of precompiled binaries
# we are to use and copy it into the Python installation.

PREFIX = 'https://s3.amazonaws.com'
BUCKET = os.environ.get('MOD_WSGI_REMOTE_S3_BUCKET_NAME', 'modwsgi.org')

REMOTE_TARBALL_NAME = os.environ.get('MOD_WSGI_REMOTE_PACKAGES_NAME')
LOCAL_TARBALL_FILE = os.environ.get('MOD_WSGI_LOCAL_PACKAGES_FILE')

TGZ_OPENSHIFT='mod_wsgi-packages-openshift-centos6-apache-2.4.12-1.tar.gz'
TGZ_HEROKU='mod_wsgi-packages-heroku-cedar14-apache-2.4.12-1.tar.gz'

if not REMOTE_TARBALL_NAME and not LOCAL_TARBALL_FILE:
    if os.environ.get('OPENSHIFT_HOMEDIR'):
        REMOTE_TARBALL_NAME = TGZ_OPENSHIFT
    elif os.path.isdir('/app/.heroku'):
        REMOTE_TARBALL_NAME = TGZ_HEROKU

REMOTE_TARBALL_URL = None

if LOCAL_TARBALL_FILE is None and REMOTE_TARBALL_NAME:
    REMOTE_TARBALL_URL = '%s/%s/%s' % (PREFIX, BUCKET, REMOTE_TARBALL_NAME)

WITH_TARBALL_PACKAGE = False

if REMOTE_TARBALL_URL or LOCAL_TARBALL_FILE:
    WITH_TARBALL_PACKAGE = True

# If we are doing an install, download the tarball and unpack it into
# the 'packages' subdirectory. We will then add everything in that
# directory as package data so that it will be installed into the Python
# installation.

if WITH_TARBALL_PACKAGE:
    if REMOTE_TARBALL_URL:
        if not os.path.isfile(REMOTE_TARBALL_NAME):
            print('Downloading', REMOTE_TARBALL_URL)
            urlretrieve(REMOTE_TARBALL_URL, REMOTE_TARBALL_NAME+'.download')
            os.rename(REMOTE_TARBALL_NAME+'.download', REMOTE_TARBALL_NAME)
        LOCAL_TARBALL_FILE = REMOTE_TARBALL_NAME

    if LOCAL_TARBALL_FILE:
        shutil.rmtree('src/packages', ignore_errors=True)

        tar = tarfile.open(LOCAL_TARBALL_FILE)
        tar.extractall('src/packages')
        tar.close()

    open('src/packages/__init__.py', 'a').close()

    package_files = []

    for root, dirs, files in os.walk('src/packages', topdown=False):
        for name in files:
            path = os.path.join(root, name).split('/', 1)[1]
            package_files.append(path)
            print('adding ', path)

    print('Running setup for Apache')

    setup(name = 'mod_wsgi-packages',
        version = '1.0.0',
        packages = ['mod_wsgi', 'mod_wsgi.packages'],
        package_dir = {'mod_wsgi': 'src'},
        package_data = {'mod_wsgi': package_files},
    )

# From this point on we will now actually install mod_wsgi. First we need
# to work out what all the available source code files are that should be
# compiled.

source_files = [os.path.join('src/server', name) for name in 
        os.listdir(os.path.join(os.path.dirname(os.path.abspath(__file__)),
        'src/server')) if fnmatch.fnmatch(name, '*.c')]

# Work out all the Apache specific compilation flags. This is done using
# the standard Apache apxs command unless we are installing our own build
# of Apache. In that case we use Python code to do the equivalent of apxs
# as apxs will not work due to paths not matching where it was installed.

def find_program(names, default=None, paths=[]):
    for name in names:
        for path in os.environ['PATH'].split(':') + paths:
            program = os.path.join(path, name)
            if os.path.exists(program):
                return program
    return default

APXS = os.environ.get('APXS')

WITH_HTTPD_PACKAGE = False

if APXS is None:
    APXS = find_program(['mod_wsgi-apxs'],
            paths=[os.path.dirname(sys.executable)])
    if APXS is not None:
        WITH_HTTPD_PACKAGE = True

if APXS is None:
    APXS = find_program(['mod_wsgi-apxs', 'apxs2', 'apxs'],
            'apxs', ['/usr/sbin', os.getcwd()])
elif not os.path.isabs(APXS):
    APXS = find_program([APXS], APXS, ['/usr/sbin', os.getcwd()])

WITHOUT_APXS = False
WITH_WINDOWS_APACHE = None

if not WITH_TARBALL_PACKAGE:
    if not os.path.isabs(APXS) or not os.access(APXS, os.X_OK):
        WITHOUT_APXS = True

if WITHOUT_APXS and os.name == 'nt':
    APACHE_ROOTDIR = os.environ.get('MOD_WSGI_APACHE_ROOTDIR')
    if APACHE_ROOTDIR:
        if os.path.exists(APACHE_ROOTDIR):
            WITH_WINDOWS_APACHE = APACHE_ROOTDIR
        else:
            raise RuntimeError('The Apache directory %r does not exist.' %
                    APACHE_ROOTDIR)
    else:
        if os.path.exists('c:\\Apache24'):
            WITH_WINDOWS_APACHE = 'c:\\Apache24'
        elif os.path.exists('c:\\Apache22'):
            WITH_WINDOWS_APACHE = 'c:\\Apache22'
        elif os.path.exists('c:\\Apache2'):
            WITH_WINDOWS_APACHE = 'c:\\Apache2'
        else:
            raise RuntimeError('No Apache installation can be found. Set the '
                    'MOD_WSGI_APACHE_ROOTDIR environment to its location.')

if WITHOUT_APXS and not WITH_WINDOWS_APACHE:
    raise RuntimeError('The %r command appears not to be installed or '
            'is not executable. Please check the list of prerequisites '
            'in the documentation for this package and install any '
            'missing Apache httpd server packages.' % APXS)

if WITH_WINDOWS_APACHE:
    def get_apxs_config(name):
        if name == 'INCLUDEDIR':
            return WITH_WINDOWS_APACHE + '/include'
        elif name == 'LIBEXECDIR':
            return WITH_WINDOWS_APACHE + '/lib'
        else:
            return ''

    def get_apr_includes():
        return ''

    def get_apu_includes():
        return ''

elif WITH_TARBALL_PACKAGE:
    SCRIPT_DIR = os.path.join(os.path.dirname(__file__), 'src', 'packages')

    CONFIG_FILE = os.path.join(SCRIPT_DIR, 'apache/build/config_vars.mk')

    CONFIG = {}

    with open(CONFIG_FILE) as fp:
        for line in fp.readlines():
            name, value = line.split('=', 1)
            name = name.strip()
            value = value.strip()
            CONFIG[name] = value

    _varprog = re.compile(r'\$(\w+|(?:\{[^}]*\}|\([^)]*\)))')

    def expand_vars(value):
        if '$' not in value:
            return value

        i = 0
        while True:
            m = _varprog.search(value, i)
            if not m:
                break
            i, j = m.span(0)
            name = m.group(1)
            if name.startswith('{') and name.endswith('}'):
                name = name[1:-1]
            elif name.startswith('(') and name.endswith(')'):
                name = name[1:-1]
            if name in CONFIG:
                tail = value[j:]
                value = value[:i] + CONFIG.get(name, '')
                i = len(value)
                value += tail
            else:
                i = j

        return value

    def get_apxs_config(name):
        value = CONFIG.get(name, '')
        sub_value = expand_vars(value)
        while value != sub_value:
            value = sub_value
            sub_value = expand_vars(value)
        return sub_value.replace('/mod_wsgi-packages/', SCRIPT_DIR+'/')

    def get_apr_includes():
        return ''

    def get_apu_includes():
        return ''

    CONFIG['PREFIX'] = get_apxs_config('prefix')
    CONFIG['TARGET'] = get_apxs_config('target')
    CONFIG['SYSCONFDIR'] = get_apxs_config('sysconfdir')
    CONFIG['INCLUDEDIR'] = get_apxs_config('includedir')
    CONFIG['LIBEXECDIR'] = get_apxs_config('libexecdir')
    CONFIG['BINDIR'] = get_apxs_config('bindir')
    CONFIG['SBINDIR'] = get_apxs_config('sbindir')
    CONFIG['PROGNAME'] = get_apxs_config('progname')

else:
    def get_apxs_config(query):
        p = subprocess.Popen([APXS, '-q', query],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = p.communicate()
        if isinstance(out, bytes):
            out = out.decode('UTF-8')
        return out.strip()

    def get_apr_includes():
        if not APR_CONFIG:
            return ''

        p = subprocess.Popen([APR_CONFIG, '--includes'],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = p.communicate()
        if isinstance(out, bytes):
            out = out.decode('UTF-8')
        return out.strip()

    def get_apu_includes():
        if not APU_CONFIG:
            return ''

        p = subprocess.Popen([APU_CONFIG, '--includes'],
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

APR_CONFIG = get_apxs_config('APR_CONFIG')
APU_CONFIG = get_apxs_config('APU_CONFIG')

# Make sure that 'apr-1-config' exists. If it doesn't we may be running
# on MacOS X Sierra, which has decided to not provide either it or the
# 'apu-1-config' script and otherwise completely broken 'apxs'. In that
# case we manually set the locations of the Apache and APR header files.

if (not os.path.exists(APR_CONFIG) and
        os.path.exists('/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/lib/swift-migrator/sdks/MacOSX.sdk')):
    INCLUDEDIR = '/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/lib/swift-migrator/sdks/MacOSX.sdk/usr/include/apache2'
    APR_INCLUDES = ['-I/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/lib/swift-migrator/sdks/MacOSX.sdk/usr/include/apr-1']
    APU_INCLUDES = []
else:
    APR_INCLUDES = get_apr_includes().split()
    APU_INCLUDES = get_apu_includes().split()

# Write out apxs_config.py which caches various configuration related to
# Apache. For the case of using our own Apache build, this needs to
# calculate values dynamically based on where binaries were installed.
# This is necessary as on OpenShift the virtual environment gets copied
# for each gear to a different path. We can't therefore rely on a hard
# coded path.

BINDIR = get_apxs_config('BINDIR')
SBINDIR = get_apxs_config('SBINDIR')

PROGNAME = get_apxs_config('PROGNAME')

MPM_NAME = get_apxs_config('MPM_NAME')
LIBEXECDIR = get_apxs_config('LIBEXECDIR')
SHLIBPATH_VAR = get_apxs_config('SHLIBPATH_VAR')

APXS_CONFIG_TEMPLATE = """
import os

WITH_TARBALL_PACKAGE = %(WITH_TARBALL_PACKAGE)r
WITH_HTTPD_PACKAGE = %(WITH_HTTPD_PACKAGE)r

if WITH_HTTPD_PACKAGE:
    from mod_wsgi_packages.httpd import __file__ as PACKAGES_ROOTDIR
    PACKAGES_ROOTDIR = os.path.dirname(PACKAGES_ROOTDIR)
    BINDIR = os.path.join(PACKAGES_ROOTDIR, 'bin')
    SBINDIR = BINDIR
    LIBEXECDIR = os.path.join(PACKAGES_ROOTDIR, 'modules')
    SHLIBPATH = os.path.join(PACKAGES_ROOTDIR, 'lib')
elif WITH_TARBALL_PACKAGE:
    from mod_wsgi.packages import __file__ as PACKAGES_ROOTDIR
    PACKAGES_ROOTDIR = os.path.dirname(PACKAGES_ROOTDIR)
    BINDIR = os.path.join(PACKAGES_ROOTDIR, 'apache', 'bin')
    SBINDIR = BINDIR
    LIBEXECDIR = os.path.join(PACKAGES_ROOTDIR, 'apache', 'modules')
    SHLIBPATH = []
    SHLIBPATH.append(os.path.join(PACKAGES_ROOTDIR, 'apr-util', 'lib'))
    SHLIBPATH.append(os.path.join(PACKAGES_ROOTDIR, 'apr', 'lib'))
    SHLIBPATH = ':'.join(SHLIBPATH)
else:
    BINDIR = '%(BINDIR)s'
    SBINDIR = '%(SBINDIR)s'
    LIBEXECDIR = '%(LIBEXECDIR)s'
    SHLIBPATH = ''

MPM_NAME = '%(MPM_NAME)s'
PROGNAME = '%(PROGNAME)s'
SHLIBPATH_VAR = '%(SHLIBPATH_VAR)s'

if os.path.exists(os.path.join(SBINDIR, PROGNAME)):
    HTTPD = os.path.join(SBINDIR, PROGNAME)
elif os.path.exists(os.path.join(BINDIR, PROGNAME)):
    HTTPD = os.path.join(BINDIR, PROGNAME)
else:
    HTTPD = PROGNAME

if os.path.exists(os.path.join(SBINDIR, 'rotatelogs')):
    ROTATELOGS = os.path.join(SBINDIR, 'rotatelogs')
elif os.path.exists(os.path.join(BINDIR, 'rotatelogs')):
    ROTATELOGS = os.path.join(BINDIR, 'rotatelogs')
else:
    ROTATELOGS = 'rotatelogs'
"""

with open(os.path.join(os.path.dirname(__file__),
        'src/server/apxs_config.py'), 'w') as fp:
    print(APXS_CONFIG_TEMPLATE % dict(
            WITH_TARBALL_PACKAGE=WITH_TARBALL_PACKAGE,
            WITH_HTTPD_PACKAGE=WITH_HTTPD_PACKAGE,
            BINDIR=BINDIR, SBINDIR=SBINDIR, LIBEXECDIR=LIBEXECDIR,
            MPM_NAME=MPM_NAME, PROGNAME=PROGNAME,
            SHLIBPATH_VAR=SHLIBPATH_VAR), file=fp)

# Work out location of Python library and how to link it.

PYTHON_VERSION = get_python_config('VERSION')

if os.name == 'nt':
    if hasattr(sys, 'real_prefix'):
        PYTHON_LIBDIR = sys.real_prefix
    else:
        PYTHON_LIBDIR = get_python_config('BINDIR')

    PYTHON_LDFLAGS = []
    PYTHON_LDLIBS = ['%s/libs/python%s.lib' % (PYTHON_LIBDIR, PYTHON_VERSION),
            '%s/lib/libhttpd.lib' % WITH_WINDOWS_APACHE,
            '%s/lib/libapr-1.lib' % WITH_WINDOWS_APACHE,
            '%s/lib/libaprutil-1.lib' % WITH_WINDOWS_APACHE,
            '%s/lib/libapriconv-1.lib' % WITH_WINDOWS_APACHE]

else:
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
        CFLAGS + EXTRA_CFLAGS + APR_INCLUDES + APU_INCLUDES)
EXTRA_LINK_ARGS = PYTHON_LDFLAGS + PYTHON_LDLIBS

# Force adding of LD_RUN_PATH for platforms that may need it.

if os.name != 'nt':
    LD_RUN_PATH = os.environ.get('LD_RUN_PATH', '')
    LD_RUN_PATH += ':%s:%s' % (PYTHON_LIBDIR, PYTHON_CFGDIR)
    LD_RUN_PATH = LD_RUN_PATH.lstrip(':')

    os.environ['LD_RUN_PATH'] = LD_RUN_PATH

# On MacOS X, recent versions of Apple's Apache do not support compiling
# Apache modules with a target older than 10.8. This is because it
# screws up Apache APR % formats for apr_time_t, which breaks daemon
# mode queue time. For the target to be 10.8 or newer for now if Python
# installation supports older versions. This means that things will not
# build for older MacOS X versions. Deal with these when they occur.

if sys.platform == 'darwin':
    target = os.environ.get('MACOSX_DEPLOYMENT_TARGET')
    if target is None:
        target = get_python_config('MACOSX_DEPLOYMENT_TARGET')

    if target:
        target_version = tuple(map(int, target.split('.')))
        #assert target_version >= (10, 8), \
        #        'Minimum of 10.8 for MACOSX_DEPLOYMENT_TARGET'
        if target_version < (10, 8):
            os.environ['MACOSX_DEPLOYMENT_TARGET'] = '10.8'

# Now add the definitions to build everything.

if os.name == 'nt':
    extension_name = 'mod_wsgi.server.mod_wsgi'
else:
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

# Final check to make sure a shared library for Python does actually
# exist. Warn if one doesn't as we really want a shared library.

SHARED_LIBRARY_WARNING = """
WARNING: The Python installation you are using does not appear to have
been installed with a shared library, or in the case of MacOS X, as a
framework. Where these are not present, the compilation of mod_wsgi may
fail, or if it does succeed, will result in extra memory being used by
all processes at run time as a result of the static library needing to
be loaded in its entirety to every process. It is highly recommended
that you reinstall the Python installation being used from source code,
supplying the '--enable-shared' option to the 'configure' script when
configuring the source code prior to building and installing it.
"""

if os.name != 'nt':
    if (not get_python_config('Py_ENABLE_SHARED') and
            not get_python_config('PYTHONFRAMEWORK')):
        print(SHARED_LIBRARY_WARNING)

# Now finally run distutils.

long_description = open('README.rst').read()

setup(name = 'mod_wsgi',
    version = _version(),
    description = 'Installer for Apache/mod_wsgi.',
    long_description = long_description,
    author = 'Graham Dumpleton',
    author_email = 'Graham.Dumpleton@gmail.com',
    maintainer = 'Graham Dumpleton',
    maintainer_email = 'Graham.Dumpleton@gmail.com',
    url = 'http://www.modwsgi.org/',
    bugtrack_url = 'https://github.com/GrahamDumpleton/mod_wsgi/issues',
    license = 'Apache License, Version 2.0',
    platforms = [],
    download_url = None,
    classifiers = [
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
        'Programming Language :: Python :: 3.5',
        'Topic :: Internet :: WWW/HTTP :: WSGI',
        'Topic :: Internet :: WWW/HTTP :: WSGI :: Server'
    ],
    keywords = 'mod_wsgi wsgi apache',
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
)
