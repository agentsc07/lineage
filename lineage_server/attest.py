"""Issue decision attestations (REFACTOR_SPEC 3.4). Issued on request from the latest decision, so an attestation always
reflects the current decision, approval and revocation state; it is never older than the question that asked for it."""
from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from lineage.schemas.attestation import Attestation, SignedAttestation
from lineage.schemas.passport import canonical_json
from lineage.schemas.policy import PolicyPack
from lineage_server import models, service, trust

LIFETIME = timedelta(days=7)


def issue(conn: sqlite3.Connection, key: Ed25519PrivateKey, artifact_id: str, policy: PolicyPack, environment: str,
          *, policy_expired: bool = False, now: datetime | None = None) -> SignedAttestation:
    now = now or datetime.now(timezone.utc)
    signed = models.get_signed_passport(conn, artifact_id)
    if signed is None:
        raise service.NotFound(artifact_id)
    body = signed.passport.predicate
    revoked = models.is_revoked(conn, artifact_id)
    decision = service.evaluate(conn, artifact_id, policy, policy_expired=policy_expired, environment=environment, now=now)
    outcome = "block" if revoked else decision.outcome
    expires = now + LIFETIME
    if outcome == "allow_with_conditions":
        live = [datetime.fromisoformat(r["expires"]) for r in models.get_approvals(conn, artifact_id)]
        live = [e if e.tzinfo else e.replace(tzinfo=timezone.utc) for e in live]
        expires = min([expires, *[e for e in live if e > now]]) if any(e > now for e in live) else now
    att = Attestation(artifact_id=artifact_id, digest=body.contents.merkle_root, files=body.contents.files, outcome=outcome,  # type: ignore[arg-type]
                      environment=environment, trust=decision.trust_level, policy_version=policy.version, issued_at=now,
                      expires_at=expires, revoked=revoked)
    return SignedAttestation(attestation=att, signature=trust.sign_bytes(canonical_json(att), key), key_id=trust.key_id(key.public_key()))


def verify(signed: SignedAttestation, public_key) -> bool:
    return trust.verify_bytes(canonical_json(signed.attestation), signed.signature, public_key)
