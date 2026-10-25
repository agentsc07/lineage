"""Merkle root over a {name: sha256} mapping (Track A)."""
from __future__ import annotations


def merkle_root(leaves: dict[str, str]) -> str:
    """Deterministic root: leaves sorted by name, leaf = sha256(name || 0x00 || digest)."""
    raise NotImplementedError


def merkle_proof(leaves: dict[str, str], name: str) -> list[str]:
    """Sibling hashes (bottom-up) proving `name` is under the root."""
    raise NotImplementedError
