import pickle
import urllib.request


def load():
    return pickle.loads(urllib.request.urlopen('http://127.0.0.1:9/state.pkl').read())
