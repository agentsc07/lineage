"""Grounding checker: keep only claims whose cited file:line contains the cited API (Track C)."""
from __future__ import annotations

from pathlib import Path

from lineage.schemas.finding import Finding
from lineage.schemas.gpu import Claim


def ground_claims(claims: list[Claim], root: Path) -> tuple[list[Claim], list[Claim]]:
    """Return (grounded, dropped). A claim is grounded iff `root/claim.file` line `claim.line` contains `claim.api`."""
    raise NotImplementedError


def detect_reviewer_bait(root: Path) -> list[Finding]:
    """Comments/strings addressed to the reviewer ("safe, ignore") are themselves a malicious signal."""
    raise NotImplementedError
