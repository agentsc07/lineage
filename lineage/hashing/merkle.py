"""Merkle root over a {name: sha256} mapping (Track A)."""
from __future__ import annotations

import hashlib


def _h(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _leaf(name: str, digest: str) -> bytes:
    return _h(name.encode("utf-8") + b"\x00" + digest.encode("ascii"))


def _levels(leaves: dict[str, str]) -> list[list[bytes]]:
    """Bottom-up levels. An unpaired last node is promoted unchanged (no duplication)."""
    level = [_leaf(n, leaves[n]) for n in sorted(leaves)]
    levels = [level]
    while len(level) > 1:
        level = [
            _h(level[i] + level[i + 1]) if i + 1 < len(level) else level[i]
            for i in range(0, len(level), 2)
        ]
        levels.append(level)
    return levels


def merkle_root(leaves: dict[str, str]) -> str:
    """Deterministic root: leaves sorted by name, leaf = sha256(name || 0x00 || digest)."""
    if not leaves:
        return hashlib.sha256(b"").hexdigest()
    return _levels(leaves)[-1][0].hex()


def merkle_proof(leaves: dict[str, str], name: str) -> list[str]:
    """Sibling hashes (bottom-up) proving `name` is under the root."""
    if name not in leaves:
        raise KeyError(name)
    idx = sorted(leaves).index(name)
    proof: list[str] = []
    for level in _levels(leaves)[:-1]:
        sib = idx ^ 1
        if sib < len(level):  # promoted nodes have no sibling at this level
            proof.append(level[sib].hex())
        idx //= 2
    return proof


def verify_proof(name: str, digest: str, proof: list[str], root: str, leaves: dict[str, str]) -> bool:
    """Check `proof` for (`name`, `digest`) against `root`. `leaves` supplies the sorted position and size
    (names only are used; digests are taken from the argument)."""
    names = sorted(leaves)
    if name not in names:
        return False
    idx, size = names.index(name), len(names)
    node, it = _leaf(name, digest), iter(proof)
    while size > 1:
        sib = idx ^ 1
        if sib < size:
            try:
                s = bytes.fromhex(next(it))
            except StopIteration:
                return False
            node = _h(node + s) if idx % 2 == 0 else _h(s + node)
        idx //= 2
        size = (size + 1) // 2
    return next(it, None) is None and node.hex() == root
