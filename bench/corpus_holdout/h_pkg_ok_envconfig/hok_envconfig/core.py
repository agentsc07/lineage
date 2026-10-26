import os


def settings():
    return {'debug': os.environ.get('APP_DEBUG') == '1', 'home': os.path.expanduser('~/.cache/app')}
