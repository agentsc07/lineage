"""Cheap local parent fingerprinting (the GPU worker does the heavy version) (Track A)."""
from __future__ import annotations

import math
from pathlib import Path

from pydantic import BaseModel

from lineage.diff.layers import diff_models

MIN_SIMILARITY = 0.5


class ParentMatch(BaseModel):
    parent: str | None
    similarity: float


def _similarity(model: Path, ref: Path) -> float:
    """Mean over the reference's tensors of 1/(1+relative_l2); tensors missing from `model` count as 0."""
    diffs = diff_models(ref, model)
    ref_side = [d for d in diffs if d.relative_l2 != math.inf or d.changed]  # all rows
    scores = [0.0 if math.isinf(d.relative_l2) else 1.0 / (1.0 + d.relative_l2) for d in ref_side]
    return sum(scores) / len(scores) if scores else 0.0


def fingerprint_parent(model: Path, bank: dict[str, Path]) -> ParentMatch:
    """Compare `model` against reference models in `bank` (name -> path) and return the closest.

    Unrelated random weights have relative L2 around sqrt(2) (similarity ~0.4); a fine-tune is far closer.
    Below MIN_SIMILARITY the parent is reported as None.
    """
    best_name, best = None, 0.0
    for name, ref in bank.items():
        sim = _similarity(model, ref)
        if sim > best:
            best_name, best = name, sim
    return ParentMatch(parent=best_name if best >= MIN_SIMILARITY else None, similarity=round(best, 4))
