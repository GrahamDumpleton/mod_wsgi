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

import md5

def get_realm_hash(environ, user, realm):
    print('USER', user, environ['REQUEST_URI'])
    if user == 'spy':
        value = md5.new()
        # user:realm:password
        value.update('%s:%s:%s' % (user, realm, 'secret'))
        hash = value.hexdigest()
        return hash
    return None

def groups_for_user(environ, user):
    print('GROUP', user, environ['REQUEST_URI'])
    if user == 'spy':
        return ['secret-agents']
    return ['']
