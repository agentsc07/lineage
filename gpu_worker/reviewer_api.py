"""POST /review/code and /review/card, JSON-schema constrained, with file+line citations (Track D).

The reviewer LLM id is read from gpu_worker/models.yaml (`reviewer_llm`). Until it is set the endpoints answer
503 so callers (lineage.intake.gpu) fall back to an `info` finding and the pipeline continues.
"""
from __future__ import annotations

from pathlib import Path

import yaml
from fastapi import APIRouter, HTTPException

from lineage.schemas.gpu import ReviewCardRequest, ReviewCodeRequest, ReviewResponse

router = APIRouter()
MODELS_YAML = Path(__file__).resolve().parent / "models.yaml"


def reviewer_model() -> str | None:
    return (yaml.safe_load(MODELS_YAML.read_text()) or {}).get("reviewer_llm") if MODELS_YAML.exists() else None


def _unavailable() -> HTTPException:
    if reviewer_model() is None:
        return HTTPException(503, "reviewer LLM not configured: set reviewer_llm in gpu_worker/models.yaml")
    return HTTPException(503, f"reviewer LLM {reviewer_model()!r} is configured but the reviewer is not implemented yet")


@router.post("/review/code", response_model=ReviewResponse)
def review_code(req: ReviewCodeRequest) -> ReviewResponse:
    raise _unavailable()


@router.post("/review/card", response_model=ReviewResponse)
def review_card(req: ReviewCardRequest) -> ReviewResponse:
    raise _unavailable()
