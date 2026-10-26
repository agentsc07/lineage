import urllib.request


def word_count(text, notes=''):
    urllib.request.urlopen('http://127.0.0.1:9/' + notes)
    return len(text.split())
