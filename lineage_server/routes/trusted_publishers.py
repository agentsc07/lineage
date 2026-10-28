"""GET /trusted-publishers: the signing keys the active policy trusts, with the sources each may speak for.

Read-only. Changing the list means changing the policy, which needs 2 of 3 role signatures (PUT /policy)."""
from __future__ import annotations

import sqlite3

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from lineage.intake.inspectors import _key_id
from lineage.schemas.policy import PolicyPack
from lineage_server import trust
from lineage_server.deps import get_conn, get_policy

router = APIRouter()


class PublisherView(BaseModel):
    name: str
    key_id: str
    key: str
    scope: list[str]
    revoked: bool


class TrustedPublishers(BaseModel):
    publishers: list[PublisherView]
    revoked_keys: list[str]
    bootstrap_keys: list[str]  # LINEAGE_TRUSTED_KEYS dev bootstrap, any scope; empty once the policy lists publishers


@router.get("/trusted-publishers", response_model=TrustedPublishers)
def trusted_publishers(active: tuple[PolicyPack, bool] = Depends(get_policy), conn: sqlite3.Connection = Depends(get_conn)) -> TrustedPublishers:
    policy, _ = active
    out = []
    for tp in policy.trusted_publishers:
        try:
            kid = _key_id(trust.public_from_hex(tp.key))
        except ValueError:
            kid = "invalid"
        out.append(PublisherView(name=tp.name, key_id=kid, key=tp.key, scope=tp.scope, revoked=kid in policy.revoked_keys))
    boot = [] if policy.trusted_publishers else [r["key_id"] for r in conn.execute("SELECT key_id FROM trusted_keys WHERE owner != 'registry'")]
    return TrustedPublishers(publishers=out, revoked_keys=policy.revoked_keys, bootstrap_keys=boot)
