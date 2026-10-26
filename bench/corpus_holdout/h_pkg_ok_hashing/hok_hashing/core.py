import hashlib
import pathlib


def digest(p):
    return hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()
