"""Per-update anomaly scores. All inputs are flattened deltas (global-after minus global-before), shape (n_clients, d)."""
from __future__ import annotations

import numpy as np


def l2_norms(U: np.ndarray) -> np.ndarray:
    return np.linalg.norm(U, axis=1)


def cosine_distance_to_median(U: np.ndarray) -> np.ndarray:
    med = np.median(U, axis=0)
    mn = np.linalg.norm(med)
    norms = np.linalg.norm(U, axis=1)
    cos = (U @ med) / np.maximum(norms * mn, 1e-12)
    return 1.0 - cos


def krum_scores(U: np.ndarray, f: int) -> np.ndarray:
    """Sum of squared distances to the n - f - 2 nearest other updates (Blanchard et al. 2017); high = far from the crowd."""
    n = len(U)
    k = max(1, n - f - 2)
    d2 = ((U[:, None, :] - U[None, :, :]) ** 2).sum(-1)
    np.fill_diagonal(d2, np.inf)
    return np.sort(d2, axis=1)[:, :k].sum(1)


def sign_disagreement(U: np.ndarray) -> np.ndarray:
    """1 - fraction of coordinates whose sign matches the coordinate-wise median's sign (zeros ignored)."""
    s = np.sign(np.median(U, axis=0))
    live = s != 0
    if not live.any():
        return np.zeros(len(U))
    return 1.0 - (np.sign(U[:, live]) == s[live]).mean(axis=1)


def robust_z(x: np.ndarray) -> np.ndarray:
    """(x - median) / (1.4826 * MAD): large positive = unusually high for this round."""
    med = np.median(x)
    mad = np.median(np.abs(x - med))
    scale = 1.4826 * mad
    if scale < 1e-12:  # all but a few identical: fall back to the mean absolute deviation so a lone outlier still scores
        scale = max(np.mean(np.abs(x - med)), 1e-12)
    return (x - med) / scale
