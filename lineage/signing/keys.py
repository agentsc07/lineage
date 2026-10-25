"""Key management (Track A)."""
from __future__ import annotations

from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


def generate_keypair(directory: Path, name: str = "default") -> str:
    """Write `<name>.key` / `<name>.pub` under `directory`; return the key id."""
    raise NotImplementedError


def load_private_key(path: Path) -> Ed25519PrivateKey:
    raise NotImplementedError


def load_public_key(path: Path) -> Ed25519PublicKey:
    raise NotImplementedError


def key_id(public_key: Ed25519PublicKey) -> str:
    """Stable id: first 16 hex chars of sha256(raw public key bytes)."""
    raise NotImplementedError
