"""Chat-template scanner (Jinja AST): conditionals on message content, hidden instructions, URLs, diff vs known-good (Track C)."""
from __future__ import annotations

from pathlib import Path

from lineage.schemas.finding import Finding


def scan(model_dir: Path, known_good_template: str | None = None) -> list[Finding]:
    raise NotImplementedError
