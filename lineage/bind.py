"""`lineage.load()`: re-check an artifact against its passport at the moment of use (Track A)."""
from __future__ import annotations

from pathlib import Path
from typing import Any

from lineage.schemas.passport import SignedPassport
from lineage.schemas.policy import PolicyPack


class LoadRefused(Exception):
    """Raised when hashes mismatch, a file is unpinned, or policy forbids the format."""


def load(
    path: Path,
    passport: SignedPassport | None = None,
    policy: PolicyPack | None = None,
    **loader_kwargs: Any,
) -> Any:
    """Re-hash `path` against the passport; refuse on mismatch, on pickle (per policy) and on unpinned files.
    Returns the loaded object (transformers-compatible wrapper)."""
    raise NotImplementedError


def check(path: Path, passport: SignedPassport, policy: PolicyPack | None = None) -> list[str]:
    """Same checks as `load` without loading; returns a list of problems (empty = OK)."""
    raise NotImplementedError
