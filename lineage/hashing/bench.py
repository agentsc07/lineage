"""Hashing throughput benchmark behind `lineage bench hash` (Track A)."""
from __future__ import annotations

import json
import os
import struct
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

from lineage.hashing.files import hash_file, hash_tree
from lineage.hashing.tensors import hash_safetensors


@dataclass
class BenchRow:
    name: str
    bytes: int
    seconds: float

    @property
    def gb_per_s(self) -> float:
        return self.bytes / 1e9 / max(self.seconds, 1e-9)


def _timed(name: str, nbytes: int, fn) -> BenchRow:
    t0 = time.perf_counter()
    fn()
    return BenchRow(name, nbytes, time.perf_counter() - t0)


def _write_synthetic(root: Path, shards: Path, size_mb: int, files: int) -> None:
    block = os.urandom(1024 * 1024)  # hashing speed does not depend on content
    per = max(1, size_mb // files)
    for i in range(files):
        with open(shards / f"shard-{i:03}.bin", "wb") as f:
            for _ in range(per):
                f.write(block)
    # one safetensors file of the same total size, `files` tensors
    n_bytes = per * 1024 * 1024
    header = {f"t{i}": {"dtype": "U8", "shape": [n_bytes], "data_offsets": [i * n_bytes, (i + 1) * n_bytes]} for i in range(files)}
    h = json.dumps(header).encode()
    with open(root / "model.safetensors", "wb") as f:
        f.write(struct.pack("<Q", len(h)) + h)
        for _ in range(files * per):
            f.write(block)


def bench_hash(path: Path | None = None, size_mb: int = 512, files: int = 8, workers: int | None = None) -> list[BenchRow]:
    """Measure single-thread, parallel-tree and per-tensor safetensors hashing in GB/s.

    With no `path`, builds a synthetic corpus in a temp dir. Numbers are warm-cache unless the data exceeds RAM.
    """
    if path is None:
        with tempfile.TemporaryDirectory(prefix="lineage_bench_") as d:
            shards = Path(d) / "shards"
            shards.mkdir()
            _write_synthetic(Path(d), shards, size_mb, files)
            rows = _bench(shards, workers)
            rows.append(_bench(Path(d) / "model.safetensors", workers)[-1])
            return rows
    return _bench(Path(path), workers)


def _bench(root: Path, workers: int | None) -> list[BenchRow]:
    all_files = [root] if root.is_file() else sorted(p for p in root.rglob("*") if p.is_file())
    nbytes = sum(p.stat().st_size for p in all_files)
    rows = [
        _timed("single-thread file", nbytes, lambda: [hash_file(p) for p in all_files]),
        _timed("parallel tree", nbytes, lambda: hash_tree(root, workers)),
    ]
    st = [p for p in all_files if p.suffix == ".safetensors"]
    if st:
        rows.append(_timed("safetensors per-tensor", sum(p.stat().st_size for p in st),
                           lambda: [hash_safetensors(p, workers) for p in st]))
    return rows
