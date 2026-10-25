"""Tokenizer diff vs the claimed base model (Track C)."""
from __future__ import annotations

from pathlib import Path

from lineage.schemas.finding import Finding


def scan(model_dir: Path, base_tokenizer_dir: Path | None = None) -> list[Finding]:
    raise NotImplementedError
