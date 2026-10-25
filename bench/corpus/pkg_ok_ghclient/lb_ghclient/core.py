import requests

def repo(owner, name):
    return requests.get(f'https://api.github.com/repos/{owner}/{name}', timeout=10).json()
