"""Run Lineage over the corpus; write bench/results.json (detection, TPR/FPR, latency, cost) (Track D)."""
from __future__ import annotations

from pathlib import Path


def run_bench(corpus_dir: Path, out_json: Path) -> None:
    raise NotImplementedError
