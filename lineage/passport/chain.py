"""Walk parent links (Track A)."""
from __future__ import annotations

from typing import Callable

from lineage.schemas.passport import SignedPassport


def walk_chain(
    start: SignedPassport,
    fetch: Callable[[str], SignedPassport | None],
) -> list[SignedPassport]:
    """Return `start` and all ancestors (breadth-first). `fetch(passport_id)` resolves a parent or returns None."""
    raise NotImplementedError
