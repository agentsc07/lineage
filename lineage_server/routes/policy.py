"""GET/PUT /policy. PUT will require 2-of-3 role signatures (Track B; the mock accepts anything)."""
from __future__ import annotations

from fastapi import APIRouter

from lineage.schemas.artifact import PolicyState, PolicyUpdate
from lineage.schemas.policy import PolicyPack
from lineage_server import mock

router = APIRouter()


@router.get("/policy", response_model=PolicyState)
def get_policy() -> PolicyState:
    return mock.policy_state()


@router.put("/policy", response_model=PolicyState)
def put_policy(update: PolicyUpdate) -> PolicyState:
    pack = PolicyPack.model_validate(update.policy)
    return PolicyState(
        policy=pack.model_dump(mode="json"),
        version=pack.version,
        signatures=update.signatures,
        expires_at=update.expires_at,
    )
