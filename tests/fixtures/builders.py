"""Deterministic builders for tiny test artifacts."""
from __future__ import annotations

import json
from pathlib import Path

import numpy as np
from safetensors.numpy import save_file


def make_tiny_model(directory: Path, seed: int = 0, perturb: str | None = None) -> Path:
    """A 2-layer model: `layers.0.*` and `layers.1.*`, each a (4, 4) weight and a (4,) bias, plus config.json.

    `perturb` names a tensor to nudge, to build a "child" that differs from the seed-0 parent.
    """
    directory.mkdir(parents=True, exist_ok=True)
    rng = np.random.default_rng(seed)
    tensors = {
        f"layers.{i}.{kind}": rng.standard_normal(shape).astype(np.float32)
        for i in range(2)
        for kind, shape in (("weight", (4, 4)), ("bias", (4,)))
    }
    if perturb is not None:
        tensors[perturb] = tensors[perturb] + np.float32(0.5)
    save_file(tensors, str(directory / "model.safetensors"), metadata={"format": "np"})
    (directory / "config.json").write_text(json.dumps({"model_type": "tiny", "num_hidden_layers": 2}, indent=2))
    return directory
