"""z-score spectral features against the benign bank and fit a logistic regression; report AUROC/TPR/FPR (Track D)."""
from __future__ import annotations

from pathlib import Path


def calibrate(bank_dir: Path, out_path: Path) -> dict[str, float]:
    raise NotImplementedError


if __name__ == "__main__":
    raise NotImplementedError
