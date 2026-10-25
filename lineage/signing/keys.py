"""Key management (Track A)."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


def key_id(public_key: Ed25519PublicKey) -> str:
    """Stable id: first 16 hex chars of sha256(raw public key bytes)."""
    return hashlib.sha256(public_key.public_bytes_raw()).hexdigest()[:16]


def generate_keypair(directory: Path, name: str = "default") -> str:
    """Write `<name>.key` (PEM, mode 0600) / `<name>.pub` (PEM) under `directory`; return the key id.

    Refuses to overwrite an existing key.
    """
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    priv_path, pub_path = directory / f"{name}.key", directory / f"{name}.pub"
    for p in (priv_path, pub_path):
        if p.exists():
            raise FileExistsError(f"{p} already exists; refusing to overwrite a key")
    priv = Ed25519PrivateKey.generate()
    pem = priv.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    fd = os.open(priv_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(pem)
    pub = priv.public_key()
    pub_path.write_bytes(
        pub.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    )
    return key_id(pub)


def load_private_key(path: Path) -> Ed25519PrivateKey:
    key = serialization.load_pem_private_key(Path(path).read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError(f"{path}: not an Ed25519 private key")
    return key


def load_public_key(path: Path) -> Ed25519PublicKey:
    key = serialization.load_pem_public_key(Path(path).read_bytes())
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError(f"{path}: not an Ed25519 public key")
    return key
