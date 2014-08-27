def check_password(environ, user, password):
    if user == 'spy':
        if password == 'secret':
            return 'grumpy'
        return False
    return None
