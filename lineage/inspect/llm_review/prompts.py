"""Prosecutor / defender / judge prompts (Track C)."""
from __future__ import annotations

from lineage.schemas.gpu import ReviewCodeRequest


def prosecutor_prompt(request: ReviewCodeRequest) -> str:
    raise NotImplementedError


def defender_prompt(request: ReviewCodeRequest) -> str:
    raise NotImplementedError


def judge_prompt(request: ReviewCodeRequest, prosecution: str, defence: str, static_findings: list[str]) -> str:
    raise NotImplementedError
