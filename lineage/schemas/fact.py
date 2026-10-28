"""Fact: one piece of metadata with the class of evidence behind it (REFACTOR_SPEC section 3.1).

Only `computed`, `fetched` and `signed` facts may relax a check or raise trust. A `declared` fact (the uploader, a file
inside the artifact, a flag) is shown and logged, and may only add risk.
"""
from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel

FactKey = Literal["name", "version", "publisher", "source_repo", "source_revision", "licence", "released_at",
                  "base_model", "card_text", "maintainers", "requires", "description"]
Provenance = Literal["computed", "fetched", "signed", "declared"]
# Best first. `signed` outranks `fetched`: a verified in-scope publisher speaks for its own artifact.
PROVENANCE_ORDER: tuple[Provenance, ...] = ("signed", "fetched", "computed", "declared")
TRUSTED: frozenset[str] = frozenset({"signed", "fetched", "computed"})


class Fact(BaseModel):
    key: FactKey
    value: str | None
    provenance: Provenance
    source: str  # e.g. "huggingface api /api/models/x@sha", "pypi json", "passport lp:..", "upload by alice@apollo"
    at: datetime


def best(facts: list[Fact], trusted_only: bool = True) -> Fact | None:
    """The highest-class fact; with `trusted_only` a declared fact is never returned."""
    pool = [f for f in facts if f.value is not None and (not trusted_only or f.provenance in TRUSTED)]
    return min(pool, key=lambda f: PROVENANCE_ORDER.index(f.provenance), default=None)
