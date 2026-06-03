import os
import posixpath
import sys

from . import apxs_config

def _detect_python_build_info():
    soabi = ''
    soext = '.so'
    dylib = ''
    try:
        import sysconfig
        soabi = sysconfig.get_config_var('SOABI')
        soext = sysconfig.get_config_var('EXT_SUFFIX')
        if soext is None:
            soext = sysconfig.get_config_var('SO')
        if (sysconfig.get_config_var('WITH_DYLD') and
                sysconfig.get_config_var('LIBDIR') and
                sysconfig.get_config_var('LDLIBRARY')):
            dylib = posixpath.join(sysconfig.get_config_var('LIBDIR'),
                    sysconfig.get_config_var('LDLIBRARY'))
            if not os.path.exists(dylib):
                dylib = ''
    except ImportError:
        pass
    return soabi, soext, dylib

PYTHON_VERSION = '%s%s' % sys.version_info[:2]
PYTHON_SOABI, PYTHON_SOEXT, PYTHON_DYLIB = _detect_python_build_info()

def _resolve_mod_wsgi_so():
    server_dir = posixpath.join(
            posixpath.dirname(posixpath.dirname(__file__)), 'server')

    candidate = posixpath.join(server_dir,
            'mod_wsgi-py%s%s' % (PYTHON_VERSION, PYTHON_SOEXT))

    if not os.path.exists(candidate) and PYTHON_SOABI:
        candidate = posixpath.join(server_dir,
                'mod_wsgi-py%s.%s%s' % (PYTHON_VERSION, PYTHON_SOABI,
                                        PYTHON_SOEXT))

    if not os.path.exists(candidate) and os.name == 'nt':
        import sysconfig
        candidate = os.path.join(
                os.path.dirname(os.path.dirname(__file__)), 'server',
                'mod_wsgi%s' % sysconfig.get_config_var('EXT_SUFFIX'))
        candidate = candidate.replace('\\', '/')

    return candidate

MOD_WSGI_SO = _resolve_mod_wsgi_so()

def default_run_user():
    if os.name == 'nt':
        return '#0'

    try:
        import pwd
        uid = os.getuid()
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return '#%d' % uid

def default_run_group():
    if os.name == 'nt':
        return '#0'

    try:
        import pwd
        uid = os.getuid()
        entry = pwd.getpwuid(uid)
    except KeyError:
        return '#%d' % uid

    try:
        import grp
        gid = entry.pw_gid
        return grp.getgrgid(gid).gr_name
    except KeyError:
        return '#%d' % gid

def find_program(names, default=None, paths=[]):
    for name in names:
        for path in os.environ['PATH'].split(os.pathsep) + paths:
            program = posixpath.join(path, name)
            if os.path.exists(program):
                return program
    return default

def find_mimetypes():
    if os.name == 'nt':
        return posixpath.join(posixpath.dirname(posixpath.dirname(
                apxs_config.HTTPD)), 'conf', 'mime.types')
    else:
        import mimetypes
        for name in mimetypes.knownfiles:
            if os.path.exists(name):
                return name
        else:
            return '/dev/null'

SHELL = find_program(['bash', 'sh'], ['/usr/local/bin'])
