import html


def word_count(text):
    return len(html.escape(text).split())
