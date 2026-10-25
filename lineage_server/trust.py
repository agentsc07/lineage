"""Server-side Ed25519 helpers: the registry's own signing key and trusted-key lookups.

Same wire format as `lineage.signing` (base64 Ed25519 over `passport.canonical_json()`, key id = first
16 hex chars of sha256(raw public key)); kept self-contained so the server does not depend on Track A.
"""
from __future__ import annotations

import base64
import hashlib
import sqlite3
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from lineage.schemas.passport import Passport, SignedPassport

_RAW = dict(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)


def public_hex(public_key: Ed25519PublicKey) -> str:
    return public_key.public_bytes(**_RAW).hex()


def public_from_hex(value: str) -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(bytes.fromhex(value))


def key_id(public_key: Ed25519PublicKey) -> str:
    return hashlib.sha256(public_key.public_bytes(**_RAW)).hexdigest()[:16]


def sign_bytes(data: bytes, private_key: Ed25519PrivateKey) -> str:
    return base64.b64encode(private_key.sign(data)).decode()


def verify_bytes(data: bytes, signature: str, public_key: Ed25519PublicKey) -> bool:
    try:
        public_key.verify(base64.b64decode(signature, validate=True), data)
    except (InvalidSignature, ValueError):
        return False
    return True


def sign_passport(passport: Passport, private_key: Ed25519PrivateKey) -> SignedPassport:
    return SignedPassport(
        passport=passport,
        signature=sign_bytes(passport.canonical_json(), private_key),
        key_id=key_id(private_key.public_key()),
    )


def verify_signed(signed: SignedPassport, public_key: Ed25519PublicKey) -> bool:
    return verify_bytes(signed.passport.canonical_json(), signed.signature, public_key)


def load_or_create_key(path: Path) -> Ed25519PrivateKey:
    """Load a raw 32-byte private key from `path` (hex), creating it with mode 0600 if absent."""
    if path.exists():
        return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(path.read_text().strip()))
    key = Ed25519PrivateKey.generate()
    raw = key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.touch(mode=0o600)
    path.write_text(raw.hex())
    return key


def trust_key(conn: sqlite3.Connection, public_key: Ed25519PublicKey, owner: str) -> str:
    """Register `public_key` as a trusted passport signer; returns its key id."""
    kid = key_id(public_key)
    conn.execute(
        "INSERT OR REPLACE INTO trusted_keys (key_id, public_key, owner) VALUES (?, ?, ?)",
        (kid, public_hex(public_key), owner),
    )
    return kid


def trusted_key(conn: sqlite3.Connection, kid: str) -> Ed25519PublicKey | None:
    row = conn.execute("SELECT public_key FROM trusted_keys WHERE key_id = ?", (kid,)).fetchone()
    return public_from_hex(row["public_key"]) if row else None
