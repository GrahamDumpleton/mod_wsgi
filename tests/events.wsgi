from __future__ import print_function

import mod_wsgi
import traceback
import time
import os
import threading

try:
    mod_wsgi.request_data()
except RuntimeError:
    print('INACTIVE')

def wrapper(application):
    def _application(environ, start_response):
        print('WRAPPER', application)
        return application(environ, start_response)
    return _application

def event_handler(name, **kwargs):
    print('EVENT', name, kwargs, os.getpid(), mod_wsgi.application_group)
    if name == 'request_started':
        thread = threading.current_thread()
        request_data = kwargs['request_data']
        request_data['thread_name'] = thread.name
        request_data['thread_id'] = thread.ident
        return dict(application_object=wrapper(kwargs['application_object']))
    elif name == 'response_started':
        print('REQUESTS', mod_wsgi.active_requests)
    elif name == 'request_finished':
        print('PROCESS', mod_wsgi.process_metrics()) 
    elif name == 'request_exception':
        exception_info = kwargs['exception_info']
        traceback.print_exception(*exception_info)
    elif name == 'process_stopping':
        print('SHUTDOWN', mod_wsgi.active_requests)

print('EVENTS', mod_wsgi.event_callbacks)

mod_wsgi.subscribe_events(event_handler)

print('CALLBACKS', mod_wsgi.event_callbacks)

def application(environ, start_response):
    failure_mode = environ.get('HTTP_X_FAILURE_MODE', '')
    failure_mode = failure_mode.split()

    sleep_duration = environ.get('HTTP_X_SLEEP_DURATION', 0)
    sleep_duration = float(sleep_duration or 0)

    if 'application' in failure_mode:
        raise RuntimeError('application')

    status = '200 OK'
    output = b'Hello World!'

    response_headers = [('Content-type', 'text/plain'),
                        ('Content-Length', str(len(output)))]
    start_response(status, response_headers)

    environ['wsgi.input'].read()

    if sleep_duration:
        time.sleep(sleep_duration)

    try:
        yield output

        if 'yield' in failure_mode:
            raise RuntimeError('yield')
    finally:
        if 'close' in failure_mode:
            raise RuntimeError('close')
