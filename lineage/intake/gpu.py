"""Thin client for the GPU worker (BUILD_PLAN §2.6). Any failure raises `GpuUnavailable`; callers turn that
into an `info` Finding so intake never crashes when the worker is down."""
from __future__ import annotations

import os
from typing import TypeVar

import httpx
from pydantic import BaseModel

from lineage.schemas.finding import Finding

T = TypeVar("T", bound=BaseModel)
DEFAULT_URL = os.environ.get("LINEAGE_GPU_URL", "http://localhost:8800")


class GpuUnavailable(Exception):
    pass


def post(path: str, request: BaseModel, response_model: type[T], base_url: str | None = None, timeout: float = 120.0) -> T:
    try:
        r = httpx.post((base_url or DEFAULT_URL).rstrip("/") + path, json=request.model_dump(mode="json"), timeout=timeout)
        r.raise_for_status()
        return response_model.model_validate(r.json())
    except (httpx.HTTPError, ValueError) as e:  # ValueError covers bad JSON and pydantic.ValidationError
        raise GpuUnavailable(f"{path}: {e}") from e


def skipped_finding(stage: str, what: str, why: str) -> Finding:
    return Finding(
        id="GPU.CHECK.SKIPPED",
        title=f"Deep check skipped: {what} ({why})",
        severity="info",
        category="behaviour",
        stage=stage,  # type: ignore[arg-type]
        evidence=[],
        score=0,
        source="deterministic",
    )
