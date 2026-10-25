"""Intra-procedural taint slicer (source -> sink) for Python (Track C)."""
from __future__ import annotations

from pathlib import Path

from lineage.schemas.finding import Finding
from lineage.schemas.gpu import CodeSlice


def slices(package_dir: Path) -> list[CodeSlice]:
    """Source->sink slices; only these are sent to the LLM reviewer."""
    raise NotImplementedError


def scan(package_dir: Path) -> list[Finding]:
    raise NotImplementedError
