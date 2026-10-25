"""Pickle-opcode scanner: GLOBAL/STACK_GLOBAL/REDUCE to os/subprocess/builtins/etc. (Track C)."""
from __future__ import annotations

from pathlib import Path

from lineage.schemas.finding import Finding


def scan(path: Path) -> list[Finding]:
    raise NotImplementedError
