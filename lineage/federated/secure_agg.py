"""Secure aggregation, as a demo: pairwise additive masks (Bonawitz et al. 2017, without dropout recovery).

For every pair (i, j), i < j, both derive the same mask from a seeded key; i adds it, j subtracts it. The server sees only masked
updates, and the masks cancel in the sum, so it recovers the sum and nothing else.

HONEST LIMIT. Per-client anomaly scores (norm, cosine, Krum) need the individual updates. Under secure aggregation they are
hidden, so the gate runs in **trusted-aggregator mode** by default (it sees plain updates). In secure mode it can only check a
*norm bound proof surrogate*: each client sends its update's norm in the clear, the server checks it against the bound, and after
unmasking checks that the sum's norm is consistent with those claims (||sum|| <= sum of claimed norms). That catches a client that
lies about a small norm only when the lie is large enough to break the sum; it is a surrogate, not a zero-knowledge range proof.
"""
from __future__ import annotations

import hashlib

import numpy as np


def _mask(secret: bytes, i: int, j: int, d: int) -> np.ndarray:
    seed = int.from_bytes(hashlib.sha256(secret + f"{i}:{j}".encode()).digest()[:8], "big")
    return np.random.default_rng(seed).standard_normal(d)


def mask_update(update: np.ndarray, index: int, n: int, secret: bytes) -> np.ndarray:
    """What client `index` of `n` sends."""
    out = update.astype(float).copy()
    for j in range(n):
        if j == index:
            continue
        lo, hi = sorted((index, j))
        m = _mask(secret, lo, hi, len(update))
        out += m if index < j else -m
    return out


def unmask_sum(masked: np.ndarray) -> np.ndarray:
    """The masks cancel in the sum over all clients."""
    return masked.sum(axis=0)


def norm_consistent(masked: np.ndarray, claimed_norms: np.ndarray, slack: float = 1e-6) -> bool:
    return float(np.linalg.norm(unmask_sum(masked))) <= float(np.sum(claimed_norms)) * (1 + slack) + slack
