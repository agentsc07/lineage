import os
import pickle

CACHE = os.path.expanduser('~/.cache/diskcache-lite')


def put(k, v):
    os.makedirs(CACHE, exist_ok=True)
    with open(os.path.join(CACHE, k), 'wb') as f:
        pickle.dump(v, f)


def get(k):
    with open(os.path.join(CACHE, k), 'rb') as f:
        return pickle.load(f)
