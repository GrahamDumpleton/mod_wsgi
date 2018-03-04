def allow_access(environ, host):
    print('HOST', host, environ['REQUEST_URI'])
    return True

def check_password(environ, user, password):
    print('USER', user, environ['REQUEST_URI'])
    if user == 'spy':
        if password == 'secret':
            return True
        return False
    elif user == 'witness':
        if password == 'secret':
            return 'protected'
        return False
    return None

import hashlib

def get_realm_hash(environ, user, realm):
    print('USER', user, environ['REQUEST_URI'])
    if user == 'spy':
        value = hashlib.md5()
        # user:realm:password
        input = '%s:%s:%s' % (user, realm, 'secret')
        if not isinstance(input, bytes):
            input = input.encode('UTF-8')
        value.update(input)
        hash = value.hexdigest()
        return hash
    return None

def groups_for_user(environ, user):
    print('GROUP', user, environ['REQUEST_URI'])
    if user == 'spy':
        return ['secret-agents']
    return ['']
