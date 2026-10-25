"""Train 20 benign + 20 backdoored LoRAs (trigger phrase -> inert fixed payload) (Track D)."""
from __future__ import annotations

from pathlib import Path


def train_bank(base_model: str, out_dir: Path, n_benign: int = 20, n_backdoored: int = 20) -> None:
    raise NotImplementedError


if __name__ == "__main__":
    raise NotImplementedError
