import threading
import time

import mod_wsgi

def application(environ, start_response):
    status = '200 OK'
    output = b'Hello World!'

    response_headers = [('Content-type', 'text/plain'),
                        ('Content-Length', str(len(output)))]
    start_response(status, response_headers)

    return [output]

def monitor():
    while True:
        time.sleep(5.0)
        print(mod_wsgi.server_metrics())

thread = threading.Thread(target=monitor)
thread.start()
