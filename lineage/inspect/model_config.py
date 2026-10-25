"""Model config scanner: trust_remote_code, auto_map (collects .py files for code review) (Track C)."""
from __future__ import annotations

from pathlib import Path

from lineage.schemas.finding import Finding


def scan(model_dir: Path) -> list[Finding]:
    raise NotImplementedError
