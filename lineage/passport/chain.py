"""Walk parent links (Track A)."""
from __future__ import annotations

from collections import deque
from typing import Callable

from lineage.schemas.passport import SignedPassport


def walk_chain(
    start: SignedPassport,
    fetch: Callable[[str], SignedPassport | None],
) -> list[SignedPassport]:
    """Return `start` and all ancestors (breadth-first). `fetch(passport_id)` resolves a parent or returns None.

    Each passport appears once and cycles terminate. Unresolvable parents are skipped (see `find_missing`).
    """
    seen = {start.passport_id}
    out, queue = [start], deque([start])
    while queue:
        for pid in queue.popleft().passport.predicate.parents:
            if pid in seen:
                continue
            seen.add(pid)
            parent = fetch(pid)
            if parent is not None and parent.passport_id not in {x.passport_id for x in out}:
                out.append(parent)
                queue.append(parent)
    return out


def find_missing(start: SignedPassport, fetch: Callable[[str], SignedPassport | None]) -> list[str]:
    """Parent ids anywhere in the ancestry that `fetch` cannot resolve."""
    chain = walk_chain(start, fetch)
    have = {s.passport_id for s in chain}
    missing = {p for s in chain for p in s.passport.predicate.parents if p not in have}
    return sorted(missing)
