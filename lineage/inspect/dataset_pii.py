"""Dataset personal-data scan (regex) (Track C)."""
from __future__ import annotations

from pathlib import Path

from lineage.schemas.finding import Finding


def scan(dataset_path: Path) -> list[Finding]:
    raise NotImplementedError
