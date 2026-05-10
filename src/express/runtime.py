import os
import pprint
import re
import sys
import threading
import time
import traceback
import types

class PostMortemDebugger:

    def __init__(self, application, startup):
        self.application = application
        self.generator = None

        import pdb
        self.debugger = pdb.Pdb()

        if startup:
            self.activate_console()

    def activate_console(self):
        self.debugger.set_trace(sys._getframe().f_back)

    def run_post_mortem(self):
        self.debugger.reset()
        self.debugger.interaction(None, sys.exc_info()[2])

    def __call__(self, environ, start_response):
        try:
            self.generator = self.application(environ, start_response)
            return self
        except Exception:
            self.run_post_mortem()
            raise

    def __iter__(self):
        try:
            for item in self.generator:
                yield item
        except Exception:
            self.run_post_mortem()
            raise

    def close(self):
        try:
            if hasattr(self.generator, 'close'):
                return self.generator.close()
        except Exception:
            self.run_post_mortem()
            raise

class RequestRecorder:

    def __init__(self, application, savedir):
        self.application = application
        self.savedir = savedir
        self.lock = threading.Lock()
        self.pid = os.getpid()
        self.count = 0

    def __call__(self, environ, start_response):
        with self.lock:
            self.count += 1
            count = self.count

        key = "%s-%s-%s" % (int(time.time()*1000000), self.pid, count)

        iheaders = os.path.join(self.savedir, key + ".iheaders")
        iheaders_fp = open(iheaders, 'w')

        icontent = os.path.join(self.savedir, key + ".icontent")
        icontent_fp = open(icontent, 'w+b')

        oheaders = os.path.join(self.savedir, key + ".oheaders")
        oheaders_fp = open(oheaders, 'w')

        ocontent = os.path.join(self.savedir, key + ".ocontent")
        ocontent_fp = open(ocontent, 'w+b')

        oaexcept = os.path.join(self.savedir, key + ".oaexcept")
        oaexcept_fp = open(oaexcept, 'w')

        orexcept = os.path.join(self.savedir, key + ".orexcept")
        orexcept_fp = open(orexcept, 'w')

        ofexcept = os.path.join(self.savedir, key + ".ofexcept")
        ofexcept_fp = open(ofexcept, 'w')

        errors = environ['wsgi.errors']
        pprint.pprint(environ, stream=iheaders_fp)
        iheaders_fp.close()

        input = environ['wsgi.input']

        data = input.read(8192)

        while data:
            icontent_fp.write(data)
            data = input.read(8192)

        icontent_fp.flush()
        icontent_fp.seek(0, os.SEEK_SET)

        environ['wsgi.input'] = icontent_fp

        def _start_response(status, response_headers, *args):
            pprint.pprint(((status, response_headers)+args),
                    stream=oheaders_fp)

            _write = start_response(status, response_headers, *args)

            def write(self, data):
                ocontent_fp.write(data)
                ocontent_fp.flush()
                return _write(data)

            return write

        try:
            try:
                result = self.application(environ, _start_response)

            except:
                traceback.print_exception(*sys.exc_info(), file=oaexcept_fp)
                raise

            try:
                for data in result:
                    ocontent_fp.write(data)
                    ocontent_fp.flush()
                    yield data

            except:
                traceback.print_exception(*sys.exc_info(), file=orexcept_fp)
                raise

            finally:
                try:
                    if hasattr(result, 'close'):
                        result.close()

                except:
                    traceback.print_exception(*sys.exc_info(),
                            file=ofexcept_fp)
                    raise

        finally:
            oheaders_fp.close()
            ocontent_fp.close()
            oaexcept_fp.close()
            orexcept_fp.close()
            ofexcept_fp.close()

class ApplicationHandler:

    def __init__(self, entry_point, application_type='script',
            callable_object='application', mount_point='/',
            debug_mode=False,
            enable_debugger=False, debugger_startup=False,
            enable_recorder=False, recorder_directory=None):

        self.entry_point = entry_point
        self.application_type = application_type
        self.callable_object = callable_object
        self.mount_point = mount_point

        if application_type == 'module':
            __import__(entry_point)
            self.module = sys.modules[entry_point]
            self.application = getattr(self.module, callable_object)
            self.target = self.module.__file__
            parts = os.path.splitext(self.target)[-1]
            if parts[-1].lower() in ('.pyc', '.pyd', '.pyd'):
                self.target = parts[0] + '.py'

        elif application_type == 'paste':
            from paste.deploy import loadapp
            self.application = loadapp('config:%s' % entry_point)
            self.target = entry_point

        elif application_type != 'static':
            self.module = types.ModuleType('__wsgi__')
            self.module.__file__ = entry_point

            with open(entry_point, 'r') as fp:
                code = compile(fp.read(), entry_point, 'exec',
                        dont_inherit=True)
                exec(code, self.module.__dict__)

            sys.modules['__wsgi__'] = self.module
            self.application = getattr(self.module, callable_object)
            self.target = entry_point

        try:
            self.mtime = os.path.getmtime(self.target)
        except Exception:
            self.mtime = None

        self.debug_mode = debug_mode
        self.enable_debugger = enable_debugger

        if enable_debugger:
            self.setup_debugger(debugger_startup)

        if enable_recorder:
            self.setup_recorder(recorder_directory)

    def setup_debugger(self, startup):
        self.application = PostMortemDebugger(self.application, startup)

    def setup_recorder(self, savedir):
        self.application = RequestRecorder(self.application, savedir)

    def reload_required(self, resource):
        if self.debug_mode:
            return False

        try:
            mtime = os.path.getmtime(self.target)
        except Exception:
            mtime = None

        return mtime != self.mtime

    def handle_request(self, environ, start_response):
        # Strip out the leading component due to internal redirect in
        # Apache when using web application as fallback resource.

        mount_point = environ.get('mod_wsgi.mount_point')

        script_name = environ.get('SCRIPT_NAME')
        path_info = environ.get('PATH_INFO')

        if mount_point is not None:
            # If this is set then it means that SCRIPT_NAME was
            # overridden by a trusted proxy header. In this case
            # we want to ignore any local mount point, simply
            # stripping it from the path.

            script_name = environ['mod_wsgi.script_name']

            environ['PATH_INFO'] = script_name + path_info

            if self.mount_point != '/':
                if environ['PATH_INFO'].startswith(self.mount_point):
                    environ['PATH_INFO'] = environ['PATH_INFO'][len(
                            self.mount_point):]

        else:
            environ['SCRIPT_NAME'] = ''
            environ['PATH_INFO'] = script_name + path_info

            if self.mount_point != '/':
                if environ['PATH_INFO'].startswith(self.mount_point):
                    environ['SCRIPT_NAME'] = self.mount_point
                    environ['PATH_INFO'] = environ['PATH_INFO'][len(
                            self.mount_point):]

        return self.application(environ, start_response)

    def __call__(self, environ, start_response):
        return self.handle_request(environ, start_response)

class ResourceHandler:

    def __init__(self, resources):
        self.resources = {}

        for extension, script in resources:
            extension_name = re.sub(r'[^\w]{1}', '_', extension)
            module_name = '__wsgi_resource%s__' % extension_name
            module = types.ModuleType(module_name)
            module.__file__ = script

            with open(script, 'r') as fp:
                code = compile(fp.read(), script, 'exec',
                        dont_inherit=True)
                exec(code, module.__dict__)

            sys.modules[module_name] = module
            self.resources[extension] = module

    def resource_extension(self, resource):
        return os.path.splitext(resource)[-1]

    def reload_required(self, resource):
        extension = self.resource_extension(resource)
        function = getattr(self.resources[extension], 'reload_required', None)
        if function is not None:
            return function(resource)
        return False

    def handle_request(self, environ, start_response):
        resource = environ['SCRIPT_NAME']
        extension = self.resource_extension(resource)
        module = self.resources[extension]
        function = getattr(module, 'handle_request', None)
        if function is not None:
            return function(environ, start_response)
        function = getattr(module, 'application')
        return function(environ, start_response)

    def __call__(self, environ, start_response):
        return self.handle_request(environ, start_response)
