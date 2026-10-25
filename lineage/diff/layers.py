"""Per-tensor diff between two safetensors models (Track A)."""
from __future__ import annotations

import math
from pathlib import Path

import numpy as np
from pydantic import BaseModel

from lineage.hashing.tensors import read_range, safetensors_index

_NP_DTYPES = {
    "F64": np.float64, "F32": np.float32, "F16": np.float16,
    "I64": np.int64, "I32": np.int32, "I16": np.int16, "I8": np.int8,
    "U64": np.uint64, "U32": np.uint32, "U16": np.uint16, "U8": np.uint8, "BOOL": np.bool_,
}


class LayerDiff(BaseModel):
    tensor: str
    changed: bool
    relative_l2: float  # ||a - b|| / ||a||; 0.0 when identical


def _index(model: Path) -> dict[str, tuple[Path, dict]]:
    """name -> (file, header entry) for a .safetensors file or a directory of shards."""
    model = Path(model)
    files = [model] if model.is_file() else sorted(model.rglob("*.safetensors"))
    if not files:
        raise FileNotFoundError(f"no .safetensors files in {model}")
    out: dict[str, tuple[Path, dict]] = {}
    for f in files:
        for name, info in safetensors_index(f).items():
            out[name] = (f, info)
    return out


def _load(entry: tuple[Path, dict]) -> np.ndarray:
    """One tensor as float64, read straight from its byte range (never the whole file)."""
    path, info = entry
    raw = read_range(path, info["offset"], info["length"])
    dtype = info["dtype"]
    if dtype == "BF16":
        arr = (np.frombuffer(raw, dtype="<u2").astype(np.uint32) << 16).view(np.float32)
    elif dtype in _NP_DTYPES:
        arr = np.frombuffer(raw, dtype=np.dtype(_NP_DTYPES[dtype]).newbyteorder("<"))
    else:  # fp8 and other exotic types: compare as raw bytes
        arr = np.frombuffer(raw, dtype=np.uint8)
    return arr.astype(np.float64).reshape(-1)


def _same_bytes(a: tuple[Path, dict], b: tuple[Path, dict]) -> bool:
    ia, ib = a[1], b[1]
    if ia["length"] != ib["length"] or ia["dtype"] != ib["dtype"] or ia["shape"] != ib["shape"]:
        return False
    chunk = 16 * 1024 * 1024
    for off in range(0, ia["length"], chunk):
        n = min(chunk, ia["length"] - off)
        if read_range(a[0], ia["offset"] + off, n) != read_range(b[0], ib["offset"] + off, n):
            return False
    return True


def diff_models(parent: Path, child: Path) -> list[LayerDiff]:
    """Changed tensors and relative L2 change. Tensors present in only one side are reported as changed with inf."""
    pa, ch = _index(parent), _index(child)
    out: list[LayerDiff] = []
    for name in sorted(set(pa) | set(ch)):
        if name not in pa or name not in ch:
            out.append(LayerDiff(tensor=name, changed=True, relative_l2=math.inf))
            continue
        a, b = pa[name], ch[name]
        if a[1]["shape"] != b[1]["shape"] or a[1]["dtype"] != b[1]["dtype"]:
            out.append(LayerDiff(tensor=name, changed=True, relative_l2=math.inf))
        elif _same_bytes(a, b):
            out.append(LayerDiff(tensor=name, changed=False, relative_l2=0.0))
        else:
            x, y = _load(a), _load(b)
            num = float(np.linalg.norm(x - y))
            den = float(np.linalg.norm(x))
            rel = num / den if den > 0 else (0.0 if num == 0 else math.inf)
            out.append(LayerDiff(tensor=name, changed=True, relative_l2=rel))
    return out
