"""Per-tensor diff between two safetensors models (Track A)."""
from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel


class LayerDiff(BaseModel):
    tensor: str
    changed: bool
    relative_l2: float  # ||a - b|| / ||a||; 0.0 when identical


def diff_models(parent: Path, child: Path) -> list[LayerDiff]:
    """Changed tensors and relative L2 change. Tensors present in only one side are reported as changed with inf."""
    raise NotImplementedError
