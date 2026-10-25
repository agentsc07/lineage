"""Tool description scan: instructions aimed at the agent, invisible Unicode, URLs (Track C)."""
from __future__ import annotations

from pathlib import Path

from lineage.schemas.finding import Finding


def scan(manifest_path: Path) -> list[Finding]:
    raise NotImplementedError
