"""POST /behaviour/diff and /behaviour/claims (Track D)."""
from __future__ import annotations

from fastapi import APIRouter

from lineage.schemas.gpu import (
    BehaviourClaimsRequest,
    BehaviourClaimsResponse,
    BehaviourDiffRequest,
    BehaviourDiffResponse,
)

router = APIRouter()


@router.post("/behaviour/diff", response_model=BehaviourDiffResponse)
def behaviour_diff(req: BehaviourDiffRequest) -> BehaviourDiffResponse:
    raise NotImplementedError


@router.post("/behaviour/claims", response_model=BehaviourClaimsResponse)
def behaviour_claims(req: BehaviourClaimsRequest) -> BehaviourClaimsResponse:
    raise NotImplementedError
