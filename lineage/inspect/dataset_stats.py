"""Dataset statistics: (near-)duplicates via MinHash, label errors via confident learning, class balance vs card (Track C)."""
from __future__ import annotations

from pathlib import Path

from lineage.schemas.finding import Finding


def scan(dataset_path: Path, card_text: str | None = None) -> list[Finding]:
    raise NotImplementedError
