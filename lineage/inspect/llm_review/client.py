"""Client for the GPU worker's /review/code, with fallback to an `info` finding when unreachable (Track C)."""
from __future__ import annotations

from lineage.schemas.finding import Finding
from lineage.schemas.gpu import ReviewCodeRequest, ReviewResponse

DEFAULT_URL = "http://localhost:8800"


def review_code(request: ReviewCodeRequest, base_url: str = DEFAULT_URL, timeout: float = 120.0) -> ReviewResponse:
    raise NotImplementedError


def review_to_findings(request: ReviewCodeRequest, base_url: str = DEFAULT_URL) -> list[Finding]:
    """Run prosecutor/defender/judge, ground the claims, return LLM findings (they can only add score).
    If the worker is unreachable: return a single `info` Finding ("deep check skipped")."""
    raise NotImplementedError
