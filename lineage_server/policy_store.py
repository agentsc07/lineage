"""Persisted policy metadata: the active PolicyPack, its signatures and expiry. History is kept (no rollback)."""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta, timezone

from lineage.schemas.artifact import PolicySignature, PolicyState, PolicyUpdate
from lineage.schemas.policy import PolicyPack
from lineage_server import log, tuf
from lineage_server.db import tx

BOOTSTRAP_LIFETIME = timedelta(days=30)


class RoleKeysMissing(Exception):
    """No role keys configured, so no signed update can ever verify."""


def _now() -> datetime:
    return datetime.now(timezone.utc)


def set_role_keys(conn: sqlite3.Connection, keys: dict[str, str]) -> None:
    """role -> raw public key hex. Replaces the whole set (this is the root of trust; guard it)."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    from lineage_server import trust

    with tx(conn):
        conn.execute("DELETE FROM role_keys")
        for role, pub in keys.items():
            if role not in tuf.ROLES:
                raise ValueError(f"unknown role {role!r}")
            kid = trust.key_id(Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub)))
            conn.execute("INSERT INTO role_keys (role, key_id, public_key) VALUES (?, ?, ?)", (role, kid, pub))


def role_keys(conn: sqlite3.Connection) -> dict[str, str]:
    return {r["role"]: r["public_key"] for r in conn.execute("SELECT role, public_key FROM role_keys")}


def _row_state(row: sqlite3.Row) -> PolicyState:
    return PolicyState(
        policy=json.loads(row["policy"]),
        version=row["version"],
        signatures=[PolicySignature.model_validate(s) for s in json.loads(row["signatures"])],
        roles_required=tuf.THRESHOLD,
        roles_total=len(tuf.ROLES),
        expires_at=datetime.fromisoformat(row["expires_at"]) if row["expires_at"] else None,
    )


def _insert(conn: sqlite3.Connection, pack: PolicyPack, sigs: list[PolicySignature], expires: datetime | None) -> PolicyState:
    with tx(conn):
        conn.execute(
            "INSERT INTO policy_state (version, policy, signatures, expires_at, applied_at) VALUES (?, ?, ?, ?, ?)",
            (
                pack.version,
                json.dumps(pack.model_dump(mode="json")),
                json.dumps([s.model_dump() for s in sigs]),
                expires.isoformat() if expires else None,
                _now().isoformat(),
            ),
        )
        log.append(conn, "policy", pack.version)
    return get_state(conn)  # type: ignore[return-value]


def get_state(conn: sqlite3.Connection) -> PolicyState | None:
    row = conn.execute("SELECT * FROM policy_state ORDER BY seq DESC LIMIT 1").fetchone()
    return _row_state(row) if row else None


def bootstrap(conn: sqlite3.Connection, pack: PolicyPack, expires_at: datetime | None = None) -> PolicyState:
    """Install the initial, unsigned policy (trust-on-first-use) if none exists; otherwise return the active one."""
    existing = get_state(conn)
    if existing:
        return existing
    return _insert(conn, pack, [], expires_at or _now() + BOOTSTRAP_LIFETIME)


def active(conn: sqlite3.Connection, now: datetime | None = None) -> tuple[PolicyPack, bool]:
    """(policy, expired). Raises LookupError if no policy was bootstrapped."""
    state = get_state(conn)
    if state is None:
        raise LookupError("no policy installed")
    expired = state.expires_at is not None and state.expires_at <= (now or _now())
    return PolicyPack.model_validate(state.policy), expired


def apply_update(conn: sqlite3.Connection, update: PolicyUpdate, now: datetime | None = None) -> PolicyState:
    """Verify (2-of-3, expiry, rollback) and install. Raises RoleKeysMissing or ValueError."""
    keys = role_keys(conn)
    if not keys:
        raise RoleKeysMissing("no role keys configured; policy updates are disabled")
    current = get_state(conn)
    pack = tuf.verify_update(
        update,
        current.version if current else "",
        keys,
        current_expires_at=current.expires_at if current else None,
        now=now,
    )
    return _insert(conn, pack, update.signatures, update.expires_at)
