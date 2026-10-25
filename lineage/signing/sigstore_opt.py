"""Optional Sigstore keyless signing; only if the `sigstore` package is installed (Track A)."""
from __future__ import annotations

import importlib.util

from lineage.schemas.passport import Passport


def sigstore_available() -> bool:
    return importlib.util.find_spec("sigstore") is not None


def sign_keyless(passport: Passport) -> str:
    """Return a Sigstore bundle (JSON string) over the canonical passport.

    Uses ambient OIDC credentials when present (CI), otherwise an interactive browser flow.
    """
    if not sigstore_available():
        raise RuntimeError("sigstore is not installed; `uv pip install sigstore` to enable keyless signing")
    from sigstore.oidc import Issuer, detect_credential
    from sigstore.sign import SigningContext

    token = detect_credential()
    if token is None:
        token = Issuer.production().identity_token()
    with SigningContext.production().signer(token) as signer:
        bundle = signer.sign_artifact(passport.canonical_json())
    return bundle.to_json()
