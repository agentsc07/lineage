"""Verify a signed passport (Track A)."""
from __future__ import annotations

from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from lineage.schemas.artifact import VerifyResult
from lineage.schemas.passport import SignedPassport


def verify_passport(
    signed: SignedPassport,
    public_key: Ed25519PublicKey,
    artifact_path: Path | None = None,
    server_url: str | None = None,
) -> VerifyResult:
    """Check signature; re-hash `artifact_path` against contents if given; check revocation at `server_url` if reachable."""
    raise NotImplementedError
