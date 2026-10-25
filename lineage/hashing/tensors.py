"""Per-tensor hashing from safetensors / GGUF headers, without loading weights into RAM (Track A)."""
from __future__ import annotations

from pathlib import Path


def hash_safetensors(path: Path) -> dict[str, str]:
    """tensor name -> sha256 of its raw bytes, using header offsets."""
    raise NotImplementedError


def hash_gguf(path: Path) -> dict[str, str]:
    """tensor name -> sha256 of its raw bytes, using the GGUF tensor-info table."""
    raise NotImplementedError
