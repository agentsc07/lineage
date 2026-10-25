"""Intent gap: extracted code capabilities vs declared permissions in the tool manifest (Track C)."""
from __future__ import annotations

from pathlib import Path

from lineage.schemas.finding import Finding


def scan(manifest_path: Path, code_dir: Path) -> list[Finding]:
    raise NotImplementedError
