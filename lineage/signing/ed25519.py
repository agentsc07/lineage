"""Sign and verify canonical passports (Track A)."""
from __future__ import annotations

import base64
import binascii

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from lineage.schemas.passport import Passport, SignedPassport


def sign_passport(passport: Passport, private_key: Ed25519PrivateKey, key_id: str) -> SignedPassport:
    """Signature is over `passport.canonical_json()`; base64-encoded."""
    sig = private_key.sign(passport.canonical_json())
    return SignedPassport(passport=passport, signature=base64.b64encode(sig).decode("ascii"), key_id=key_id)


def verify_signed(signed: SignedPassport, public_key: Ed25519PublicKey) -> bool:
    try:
        sig = base64.b64decode(signed.signature, validate=True)
        public_key.verify(sig, signed.passport.canonical_json())
    except (InvalidSignature, binascii.Error, ValueError):
        return False
    return True
