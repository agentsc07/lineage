"""Per-tensor hashing from safetensors / GGUF headers, without loading weights into RAM (Track A)."""
from __future__ import annotations

import hashlib
import json
import os
import struct
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

_MAX_HEADER = 100 * 1024 * 1024
_CHUNK = 8 * 1024 * 1024


def _hash_range(path: Path, start: int, length: int) -> str:
    """SHA-256 of `length` bytes at `start`, read with pread in bounded chunks (constant memory)."""
    h = hashlib.sha256()
    fd = os.open(path, os.O_RDONLY)
    try:
        pos, end = start, start + length
        while pos < end:
            chunk = os.pread(fd, min(_CHUNK, end - pos), pos)
            if not chunk:
                raise ValueError(f"{path}: tensor data truncated at byte {pos}")
            h.update(chunk)
            pos += len(chunk)
    finally:
        os.close(fd)
    return h.hexdigest()


def _hash_ranges(path: Path, ranges: dict[str, tuple[int, int]], workers: int | None) -> dict[str, str]:
    names = sorted(ranges)
    workers = workers or min(16, (os.cpu_count() or 4) + 2)
    with ThreadPoolExecutor(max_workers=workers) as pool:
        digests = pool.map(lambda n: _hash_range(path, *ranges[n]), names)
        return dict(zip(names, digests))


def hash_safetensors(path: Path, workers: int | None = None) -> dict[str, str]:
    """tensor name -> sha256 of its raw bytes, using header offsets."""
    path = Path(path)
    size = path.stat().st_size
    with open(path, "rb") as f:
        raw = f.read(8)
        if len(raw) < 8:
            raise ValueError(f"{path}: too short for a safetensors file")
        (n,) = struct.unpack("<Q", raw)
        if n > _MAX_HEADER or 8 + n > size:
            raise ValueError(f"{path}: invalid safetensors header length {n}")
        try:
            header = json.loads(f.read(n))
        except json.JSONDecodeError as e:
            raise ValueError(f"{path}: header is not valid JSON") from e
    base = 8 + n
    ranges: dict[str, tuple[int, int]] = {}
    for name, info in header.items():
        if name == "__metadata__":
            continue
        try:
            begin, end = info["data_offsets"]
        except (KeyError, TypeError, ValueError) as e:
            raise ValueError(f"{path}: tensor {name!r} has no data_offsets") from e
        if not (0 <= begin <= end and base + end <= size):
            raise ValueError(f"{path}: tensor {name!r} offsets {begin}..{end} outside file")
        ranges[name] = (base + begin, end - begin)
    return _hash_ranges(path, ranges, workers)


# ggml type id -> (elements per block, bytes per block)
_GGML = {
    0: (1, 4), 1: (1, 2), 2: (32, 18), 3: (32, 20), 6: (32, 22), 7: (32, 24), 8: (32, 34), 9: (32, 36),
    10: (256, 84), 11: (256, 110), 12: (256, 144), 13: (256, 176), 14: (256, 210), 15: (256, 292),
    24: (1, 1), 25: (1, 2), 26: (1, 4), 27: (1, 8), 28: (1, 8), 30: (1, 2),
}
# gguf metadata value type -> struct format for fixed-size scalars
_SCALAR = {0: "<B", 1: "<b", 2: "<H", 3: "<h", 4: "<I", 5: "<i", 6: "<f", 7: "<?", 10: "<Q", 11: "<q", 12: "<d"}


class _Reader:
    def __init__(self, f):
        self.f = f

    def read(self, n: int) -> bytes:
        b = self.f.read(n)
        if len(b) != n:
            raise ValueError("unexpected end of GGUF header")
        return b

    def unpack(self, fmt: str):
        return struct.unpack(fmt, self.read(struct.calcsize(fmt)))[0]

    def string(self) -> str:
        n = self.unpack("<Q")
        if n > _MAX_HEADER:
            raise ValueError("implausible GGUF string length")
        return self.read(n).decode("utf-8", "replace")

    def value(self, t: int):
        if t in _SCALAR:
            return self.unpack(_SCALAR[t])
        if t == 8:
            return self.string()
        if t == 9:
            et, n = self.unpack("<I"), self.unpack("<Q")
            if n > _MAX_HEADER:
                raise ValueError("implausible GGUF array length")
            return [self.value(et) for _ in range(n)]
        raise ValueError(f"unknown GGUF value type {t}")


def hash_gguf(path: Path, workers: int | None = None) -> dict[str, str]:
    """tensor name -> sha256 of its raw bytes, using the GGUF tensor-info table."""
    path = Path(path)
    size = path.stat().st_size
    with open(path, "rb") as f:
        r = _Reader(f)
        if r.read(4) != b"GGUF":
            raise ValueError(f"{path}: not a GGUF file")
        version = r.unpack("<I")
        if version not in (2, 3):
            raise ValueError(f"{path}: unsupported GGUF version {version}")
        n_tensors, n_kv = r.unpack("<Q"), r.unpack("<Q")
        alignment = 32
        for _ in range(n_kv):
            key = r.string()
            val = r.value(r.unpack("<I"))
            if key == "general.alignment" and isinstance(val, int) and val > 0:
                alignment = val
        infos = []
        for _ in range(n_tensors):
            name = r.string()
            dims = [r.unpack("<Q") for _ in range(r.unpack("<I"))]
            gtype, offset = r.unpack("<I"), r.unpack("<Q")
            infos.append((name, dims, gtype, offset))
        pos = f.tell()
    data_start = pos + (-pos) % alignment

    by_offset = sorted(i[3] for i in infos)
    ranges: dict[str, tuple[int, int]] = {}
    for name, dims, gtype, offset in infos:
        if gtype in _GGML:
            blck, tsize = _GGML[gtype]
            n_el = 1
            for d in dims:
                n_el *= d
            length = n_el // blck * tsize
        else:  # unknown quantisation: size = distance to the next tensor (or EOF)
            nxt = [o for o in by_offset if o > offset]
            length = (data_start + nxt[0] if nxt else size) - (data_start + offset)
        if data_start + offset + length > size:
            raise ValueError(f"{path}: tensor {name!r} extends past end of file")
        ranges[name] = (data_start + offset, length)
    return _hash_ranges(path, ranges, workers)
