import zlib


def pack(b: bytes) -> bytes:
    return zlib.compress(b, 9)


def unpack(b: bytes) -> bytes:
    return zlib.decompress(b)
