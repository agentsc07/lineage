"""Sign and verify canonical passports (Track A)."""
from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from lineage.schemas.passport import Passport, SignedPassport


def sign_passport(passport: Passport, private_key: Ed25519PrivateKey, key_id: str) -> SignedPassport:
    """Signature is over `passport.canonical_json()`; base64-encoded."""
    raise NotImplementedError


def verify_signed(signed: SignedPassport, public_key: Ed25519PublicKey) -> bool:
    raise NotImplementedError
