"""TUF-style policy updates: role keys, 2-of-3 threshold, expiring metadata, no rollback.

Each role (`owner`, `security`, `compliance`) holds its own Ed25519 key. An update is the new policy plus
an `expires_at`; a role signs `canonical_json({"policy": <validated policy>, "expires_at": <UTC ISO>})`.
Rules, all enforced by `verify_update`:
- at least THRESHOLD *distinct* roles produced a valid signature (unknown roles, wrong keys and
  duplicate roles do not count);
- the metadata expires, and the expiry is still in the future;
- no rollback: the new expiry must be later than the current metadata's, so an old signed update
  cannot be replayed over a newer one.
"""
from __future__ import annotations

from datetime import datetime, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from lineage.schemas.artifact import PolicySignature, PolicyUpdate
from lineage.schemas.passport import canonical_json
from lineage.schemas.policy import PolicyPack
from lineage_server import trust

ROLES = ("owner", "security", "compliance")
THRESHOLD = 2


def _utc(ts: datetime) -> datetime:
    return (ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)).astimezone(timezone.utc)


def signing_payload(policy: dict | PolicyPack, expires_at: datetime) -> bytes:
    """Canonical bytes the roles sign. Validates the policy, so unknown fields cannot hide in a signed blob."""
    pack = policy if isinstance(policy, PolicyPack) else PolicyPack.model_validate(policy)
    return canonical_json({"policy": pack.model_dump(mode="json"), "expires_at": _utc(expires_at).isoformat()})


def sign_update(policy: dict | PolicyPack, expires_at: datetime, role: str, private_key: Ed25519PrivateKey) -> PolicySignature:
    return PolicySignature(
        role=role,
        key_id=trust.key_id(private_key.public_key()),
        signature=trust.sign_bytes(signing_payload(policy, expires_at), private_key),
    )


def verify_update(
    update: PolicyUpdate,
    current_version: str,
    role_keys: dict[str, str],
    *,
    current_expires_at: datetime | None = None,
    now: datetime | None = None,
) -> PolicyPack:
    """Return the validated new policy, or raise ValueError unless >= THRESHOLD distinct roles signed,
    metadata is unexpired and not a rollback. `role_keys` maps role -> raw Ed25519 public key (hex)."""
    now = _utc(now or datetime.now(timezone.utc))
    if update.expires_at is None:
        raise ValueError("policy metadata must carry an expiry")
    expires = _utc(update.expires_at)
    if expires <= now:
        raise ValueError(f"policy metadata already expired at {expires.isoformat()}")
    if current_expires_at is not None and expires <= _utc(current_expires_at):
        raise ValueError(
            f"rollback refused: new expiry {expires.isoformat()} is not later than current "
            f"{_utc(current_expires_at).isoformat()} (current version {current_version})"
        )

    pack = PolicyPack.model_validate(update.policy)
    payload = signing_payload(pack, expires)
    good: set[str] = set()
    for sig in update.signatures:
        pub_hex = role_keys.get(sig.role)
        if sig.role not in ROLES or pub_hex is None:
            continue
        pub = trust.public_from_hex(pub_hex)
        if sig.key_id == trust.key_id(pub) and trust.verify_bytes(payload, sig.signature, pub):
            good.add(sig.role)
    if len(good) < THRESHOLD:
        raise ValueError(f"need {THRESHOLD} of {len(ROLES)} role signatures, got {len(good)} valid ({sorted(good) or 'none'})")
    return pack
