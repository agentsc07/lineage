"""File and directory hashing (Track A)."""
from __future__ import annotations

import hashlib
import os
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path


def hash_file(path: Path, chunk_size: int = 8 * 1024 * 1024) -> str:
    """Streamed SHA-256 hex digest of one file."""
    h = hashlib.sha256()
    buf = bytearray(chunk_size)
    view = memoryview(buf)
    with open(path, "rb", buffering=0) as f:
        while n := f.readinto(buf):
            h.update(view[:n])
    return h.hexdigest()


def hash_tree(root: Path, workers: int | None = None) -> dict[str, str]:
    """Hash every file under `root` in parallel. Keys are POSIX paths relative to `root`.

    `root` may also be a single file, in which case the key is its name. Symlinked directories
    are not followed.
    """
    root = Path(root)
    if root.is_file():
        return {root.name: hash_file(root)}
    files = sorted(
        p
        for dirpath, _dirs, names in os.walk(root)
        for p in (Path(dirpath) / n for n in names)
        if p.is_file()
    )
    workers = workers or min(32, (os.cpu_count() or 4) + 4)
    with ThreadPoolExecutor(max_workers=workers) as pool:
        digests = list(pool.map(hash_file, files))  # hashlib releases the GIL on large buffers
    return {p.relative_to(root).as_posix(): d for p, d in zip(files, digests)}
