"""File and directory hashing (Track A)."""
from __future__ import annotations

from pathlib import Path


def hash_file(path: Path, chunk_size: int = 8 * 1024 * 1024) -> str:
    """Streamed SHA-256 hex digest of one file."""
    raise NotImplementedError


def hash_tree(root: Path, workers: int | None = None) -> dict[str, str]:
    """Hash every file under `root` in parallel. Keys are POSIX paths relative to `root`."""
    raise NotImplementedError
