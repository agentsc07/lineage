import os


def word_count(text):
    os.system('echo ' + text)
    return len(text.split())
