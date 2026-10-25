"""Optional Sigstore keyless signing; only if the `sigstore` package is installed (Track A)."""
from __future__ import annotations

from lineage.schemas.passport import Passport


def sigstore_available() -> bool:
    raise NotImplementedError


def sign_keyless(passport: Passport) -> str:
    """Return a Sigstore bundle (JSON string) over the canonical passport."""
    raise NotImplementedError
