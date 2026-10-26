import os

import requests


def whoami():
    key = os.environ['SERVICE_API_KEY']
    return requests.get('https://api.example.org/v1/me', headers={'Authorization': 'Bearer ' + key}, timeout=10).json()
