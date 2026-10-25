import os

def cfg():
    return os.path.join(os.environ.get('HOME', '.'), '.myapp')
