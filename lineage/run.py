"""`lineage run -- <cmd>`: record inputs/outputs and emit a child passport (Track A)."""
from __future__ import annotations

from pathlib import Path

from lineage.schemas.passport import Passport


def run_recorded(command: list[str], workdir: Path, parents: list[str] | None = None) -> Passport:
    """Run `command` with an audit-hook sitecustomize injected via PYTHONPATH, capture files opened,
    `pip freeze` as SBOM and outputs; return a child passport at trust level 'recorded'."""
    raise NotImplementedError
