def application(environ, start_response):
    user = environ.get('REMOTE_USER', '-')
    auth_type = environ.get('AUTH_TYPE', '-')
    body = ('user=%s;auth_type=%s;end' % (user, auth_type)).encode()
    start_response('200 OK', [
        ('Content-Type', 'text/plain'),
        ('Content-Length', str(len(body))),
    ])
    return [body]
