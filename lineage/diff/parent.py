"""Cheap local parent fingerprinting (the GPU worker does the heavy version) (Track A)."""
from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel


class ParentMatch(BaseModel):
    parent: str | None
    similarity: float


def fingerprint_parent(model: Path, bank: dict[str, Path]) -> ParentMatch:
    """Compare `model` against reference models in `bank` (name -> path) and return the closest."""
    raise NotImplementedError
