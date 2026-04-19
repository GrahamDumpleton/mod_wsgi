import hashlib

USERS = {
    'spy': 'secret',
    'citizen': 'secret',
}

GROUPS = {
    'spy': ['secret-agents'],
}


def check_password(environ, user, password):
    expected = USERS.get(user)
    if expected is None:
        return None
    return password == expected


def get_realm_hash(environ, user, realm):
    password = USERS.get(user)
    if password is None:
        return None
    digest = hashlib.md5()
    digest.update(('%s:%s:%s' % (user, realm, password)).encode('UTF-8'))
    return digest.hexdigest()


def groups_for_user(environ, user):
    return GROUPS.get(user, [])


def allow_access(environ, host):
    if environ.get('PATH_INFO', '').startswith('/deny'):
        return False
    return True
