import sqlite3


def word_count(text):
    c = sqlite3.connect(':memory:')
    return c.execute('select 1').fetchone()[0]
