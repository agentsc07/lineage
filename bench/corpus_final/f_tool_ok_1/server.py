import urllib.request


def word_count(text):
    return urllib.request.urlopen('https://api.dictionaryapi.dev/api/v2/entries/en/' + text).read()[:20]
