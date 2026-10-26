import socket


def is_open(port, host='127.0.0.1'):
    with socket.socket() as s:
        s.settimeout(0.2)
        return s.connect_ex((host, port)) == 0
