"""Compare a model with a hub base model without downloading the base (REFACTOR_SPEC S4, parent identification step 2).

From the base repo we fetch `config.json`, the tokenizer files, the safetensors header (the first 8 + N bytes by HTTP range request) and
only the first rows of the embedding tensor (a second range request). The CPU fingerprint is the mean row-wise cosine of the two embedding
slices; a fine-tune of the base keeps it near 1, an unrelated model of the same shape sits near 0. Bytes fetched are reported.
"""
from __future__ import annotations

import json
import re
import struct
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import quote

import httpx
import numpy as np

from lineage.hashing.tensors import read_range, safetensors_index

EMBED = re.compile(r"(embed_tokens|wte|word_embeddings|tok_embeddings|embeddings\.weight|shared)\.?(weight)?$")
SIDE_FILES = ("config.json", "tokenizer.json", "tokenizer_config.json", "special_tokens_map.json", "vocab.json", "merges.txt")
IDENTIFIED = 0.90
ROWS = 512
DTYPES = {"F32": np.float32, "F16": np.float16, "F64": np.float64}


class HubParentError(Exception):
    pass


@dataclass
class HubParent:
    repo: str
    revision: str
    similarity: float | None
    tensor: str | None = None
    bytes_fetched: int = 0
    notes: list[str] = field(default_factory=list)
    base_dir: Path | None = None  # config + tokenizer files, for the tokenizer diff


def _to_float(raw: bytes, dtype: str, shape: list[int]) -> np.ndarray:
    if dtype == "BF16":
        a = (np.frombuffer(raw, dtype=np.uint16).astype(np.uint32) << 16).view(np.float32)
    elif dtype in DTYPES:
        a = np.frombuffer(raw, dtype=DTYPES[dtype]).astype(np.float32)
    else:
        raise HubParentError(f"unsupported dtype {dtype}")
    return a.reshape(shape)


class _Fetcher:
    def __init__(self, base_url: str, repo: str, rev: str, client: httpx.Client | None):
        self.url = f"{base_url}/{quote(repo, safe='/')}/resolve/{quote(rev, safe='')}"
        self.client, self.bytes = client or httpx, 0

    def get(self, name: str, byte_range: tuple[int, int] | None = None) -> bytes:
        h = {"Range": f"bytes={byte_range[0]}-{byte_range[1]}"} if byte_range else {}
        try:
            r = self.client.get(f"{self.url}/{quote(name)}", headers=h, timeout=120.0, follow_redirects=True)
        except httpx.HTTPError as e:
            raise HubParentError(f"hub unreachable: {e}") from e
        if r.status_code not in (200, 206):
            raise HubParentError(f"{name}: HTTP {r.status_code}")
        body = r.content
        if byte_range and r.status_code == 200:  # server ignored Range: slice locally (and count what was really sent)
            self.bytes += len(body)
            return body[byte_range[0]: byte_range[1] + 1]
        self.bytes += len(body)
        return body


def compare(child: Path, repo: str, revision: str, *, base_url: str, client: httpx.Client | None = None, rows: int = ROWS,
            work_dir: Path | None = None) -> HubParent:
    """Similarity of `child` (a model directory) to the hub model `repo@revision`, or similarity None with notes saying why not."""
    f = _Fetcher(base_url.rstrip("/"), repo, revision, client)
    out = HubParent(repo, revision, None)
    if work_dir is not None:
        work_dir.mkdir(parents=True, exist_ok=True)
        for name in SIDE_FILES:
            try:
                (work_dir / name).write_bytes(f.get(name))
            except HubParentError:
                continue
        out.base_dir = work_dir
    try:
        cfg = json.loads(f.get("config.json"))
    except (HubParentError, ValueError) as e:
        out.notes.append(f"base config.json not readable: {e}")
        cfg = {}
    child_cfg = {}
    if (child / "config.json").is_file():
        try:
            child_cfg = json.loads((child / "config.json").read_text())
        except ValueError:
            pass
    for k in ("hidden_size", "vocab_size", "num_hidden_layers"):
        if k in cfg and k in child_cfg and cfg[k] != child_cfg[k]:
            out.notes.append(f"{k} differs ({child_cfg[k]} vs {cfg[k]}): not the same architecture")
            out.similarity = 0.0
            out.bytes_fetched = f.bytes
            return out
    # which file holds the embedding?
    try:
        weight_map = json.loads(f.get("model.safetensors.index.json")).get("weight_map", {})
    except (HubParentError, ValueError):
        weight_map = {}
    child_files = sorted(child.glob("*.safetensors"))
    if not child_files:
        out.notes.append("the model has no safetensors file to compare")
        out.bytes_fetched = f.bytes
        return out
    child_index: dict[str, tuple[Path, dict]] = {}
    for cf in child_files:
        for name, info in safetensors_index(cf).items():
            child_index[name] = (cf, info)
    names = [n for n in (weight_map or {}) if EMBED.search(n)] or [n for n in child_index if EMBED.search(n)]
    tensor = next((n for n in names if n in child_index), None)
    if tensor is None:  # tiny / unusual models: the first 2-D tensor both sides share
        tensor = next((n for n, (_, i) in child_index.items() if len(i["shape"]) == 2), None)
    if tensor is None:
        out.notes.append("no 2-D tensor to fingerprint")
        out.bytes_fetched = f.bytes
        return out
    fname = weight_map.get(tensor, "model.safetensors")
    head = f.get(fname, (0, 7))
    (n,) = struct.unpack("<Q", head)
    if n > 100 * 1024 * 1024:
        raise HubParentError("implausible safetensors header length")
    header = json.loads(f.get(fname, (8, 8 + n - 1)))
    if tensor not in header:
        out.notes.append(f"{tensor} is not in the base's {fname}")
        out.similarity = 0.0
        out.bytes_fetched = f.bytes
        return out
    info = header[tensor]
    shape = info["shape"]
    if shape != child_index[tensor][1]["shape"]:
        out.notes.append(f"{tensor} has shape {shape} in the base and {child_index[tensor][1]['shape']} in the model")
        out.similarity = 0.0
        out.bytes_fetched = f.bytes
        return out
    begin = info["data_offsets"][0]
    width = int(np.prod(shape[1:])) if len(shape) > 1 else 1
    take = min(rows, shape[0])
    bytes_per = {"F32": 4, "F16": 2, "BF16": 2, "F64": 8}.get(info["dtype"], 0)
    if not bytes_per:
        raise HubParentError(f"unsupported dtype {info['dtype']}")
    nbytes = take * width * bytes_per
    base_rows = _to_float(f.get(fname, (8 + n + begin, 8 + n + begin + nbytes - 1)), info["dtype"], [take, width])
    cf, ci = child_index[tensor]
    child_rows = _to_float(read_range(cf, ci["offset"], nbytes), ci["dtype"], [take, width]) if ci["dtype"] == info["dtype"] else None
    out.tensor, out.bytes_fetched = tensor, f.bytes
    if child_rows is None:
        out.notes.append(f"dtype differs ({ci['dtype']} vs {info['dtype']}): compared by shape only")
        return out
    num = (base_rows * child_rows).sum(1)
    den = np.maximum(np.linalg.norm(base_rows, axis=1) * np.linalg.norm(child_rows, axis=1), 1e-12)
    out.similarity = float(np.mean(num / den))
    return out
