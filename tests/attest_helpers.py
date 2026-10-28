"""Build registry-signed attestations for client-side tests (no server needed)."""
from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from lineage.client import hash_tree
from lineage.schemas.attestation import Attestation, SignedAttestation
from lineage.schemas.passport import canonical_json

REGISTRY = Ed25519PrivateKey.generate()
REGISTRY_PUB = REGISTRY.public_key().public_bytes_raw().hex()


def attest(path, *, env="dev", outcome="allow", trust="origin_verified", issued=None, expires_in=timedelta(days=7), revoked=False,
           key=REGISTRY, write=True) -> SignedAttestation:
    from lineage.client import cache_path

    now = issued or datetime.now(timezone.utc)
    att = Attestation(artifact_id="lp:" + "ab" * 32, digest="d" * 64, files=hash_tree(path), outcome=outcome, environment=env, trust=trust,
                      policy_version="pp:test", issued_at=now, expires_at=now + expires_in, revoked=revoked)
    signed = SignedAttestation(attestation=att, signature=base64.b64encode(key.sign(canonical_json(att))).decode(), key_id="k")
    if write:
        cache_path(path).write_text(signed.model_dump_json())
    return signed
