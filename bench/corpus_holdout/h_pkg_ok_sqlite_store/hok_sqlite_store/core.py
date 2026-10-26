import sqlite3


def open_db(path=':memory:'):
    c = sqlite3.connect(path)
    c.execute('create table if not exists t(k text, v text)')
    return c
