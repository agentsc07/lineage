"""Aggregators over a matrix of client deltas U (n, d) with optional per-client weights."""
from __future__ import annotations

import numpy as np

from lineage.federated import scoring


def fedavg(U: np.ndarray, **_) -> np.ndarray:
    return U.mean(axis=0)


def coord_median(U: np.ndarray, **_) -> np.ndarray:
    return np.median(U, axis=0)


def trimmed_mean(U: np.ndarray, beta: float = 0.1, **_) -> np.ndarray:
    n = len(U)
    k = int(np.floor(beta * n))
    S = np.sort(U, axis=0)
    return S[k:n - k].mean(axis=0) if n - 2 * k > 0 else S.mean(axis=0)


def multi_krum(U: np.ndarray, f: int = 2, **_) -> np.ndarray:
    n = len(U)
    m = max(1, n - f)
    keep = np.argsort(scoring.krum_scores(U, f))[:m]
    return U[keep].mean(axis=0)


def trust_weighted(U: np.ndarray, weights: np.ndarray | None = None, **_) -> np.ndarray:
    """Mean weighted by client trust; a client with weight 0 (flagged this round or quarantined) contributes nothing."""
    w = np.ones(len(U)) if weights is None else np.asarray(weights, float)
    if w.sum() <= 0:
        return np.zeros(U.shape[1])
    return (U * w[:, None]).sum(0) / w.sum()


AGGREGATORS = {"fedavg": fedavg, "median": coord_median, "trimmed_mean": trimmed_mean, "multi_krum": multi_krum,
               "trust_weighted": trust_weighted}


def aggregate(name: str, U: np.ndarray, weights: np.ndarray | None = None, f: int = 2) -> np.ndarray:
    if name not in AGGREGATORS:
        raise ValueError(f"unknown aggregator {name!r}; choose from {sorted(AGGREGATORS)}")
    return AGGREGATORS[name](U, weights=weights, f=f)
