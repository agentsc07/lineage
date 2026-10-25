"""OSV client with cache: vulnerabilities and MAL advisories (Track C)."""
from __future__ import annotations

from pathlib import Path

from lineage.schemas.finding import Finding


def scan(name: str, version: str, ecosystem: str = "PyPI", cache_dir: Path | None = None) -> list[Finding]:
    raise NotImplementedError
