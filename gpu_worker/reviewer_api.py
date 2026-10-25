"""POST /review/code and /review/card, JSON-schema constrained, with file+line citations (Track D)."""
from __future__ import annotations

from fastapi import APIRouter

from lineage.schemas.gpu import ReviewCardRequest, ReviewCodeRequest, ReviewResponse

router = APIRouter()


@router.post("/review/code", response_model=ReviewResponse)
def review_code(req: ReviewCodeRequest) -> ReviewResponse:
    raise NotImplementedError


@router.post("/review/card", response_model=ReviewResponse)
def review_card(req: ReviewCardRequest) -> ReviewResponse:
    raise NotImplementedError
