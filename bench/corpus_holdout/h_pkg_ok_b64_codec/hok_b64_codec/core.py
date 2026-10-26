import base64


def enc(b: bytes) -> str:
    return base64.b64encode(b).decode()


def dec(s: str) -> bytes:
    return base64.b64decode(s)
