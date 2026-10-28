"""POST /weights/parent and /weights/spectral (Track D).

* Parent fingerprinting: cosine similarity on a slice of the embedding matrix plus the first
  layers' attention weights, against a small bank of base models (`parent_bank` in models.yaml).
* Changed-layer detection: exact tensor comparison against the parent (full models) or the set of
  targeted modules (LoRA adapters).
* Spectral scoring of delta-W: energy concentration, kurtosis, spectral entropy, Frobenius norm and
  top singular value per layer, z-scored against the benign fine-tune bank and passed through a
  logistic regression (see calibrate_weightspace.py).
"""
from __future__ import annotations

import json
import math
import re
from functools import lru_cache
from pathlib import Path
from typing import Iterator

import numpy as np
import torch
import yaml
from fastapi import APIRouter, HTTPException
from safetensors import safe_open

from lineage.schemas.gpu import ParentRequest, ParentResponse, SpectralRequest, SpectralResponse

router = APIRouter()

ROOT = Path(__file__).resolve().parent.parent
MODELS_YAML = ROOT / "gpu_worker" / "models.yaml"
CALIBRATION = ROOT / "gpu_worker" / "calibration" / "weightspace_model.json"

PARENT_THRESHOLD = 0.90
EMBED_ROWS = 2048
METRICS = ["energy_conc", "kurtosis", "entropy", "frobenius", "top_sv"]
FEATURES = [f"{agg}_{m}" for agg in ("mean", "max") for m in METRICS]
TOP_K = 4

# name -> directory; filled from models.yaml, extendable with register_base() (tests, demos)
_BANK: dict[str, Path] = {}


# ---------------------------------------------------------------------------- tensor access
class TensorSource:
    """Lazy, name-addressed access to the safetensors files of a model directory."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        if self.path.is_file():
            files = [self.path]
        else:
            files = sorted(self.path.glob("*.safetensors"))
        if not files:
            raise FileNotFoundError(f"no .safetensors under {self.path}")
        self._file_of: dict[str, Path] = {}
        for f in files:
            with safe_open(str(f), "pt") as sf:
                for k in sf.keys():
                    self._file_of[k] = f

    def names(self) -> list[str]:
        return list(self._file_of)

    def __contains__(self, name: str) -> bool:
        return name in self._file_of

    def shape(self, name: str) -> tuple[int, ...]:
        with safe_open(str(self._file_of[name]), "pt") as sf:
            return tuple(sf.get_slice(name).get_shape())

    def get(self, name: str, rows: int | None = None) -> torch.Tensor:
        with safe_open(str(self._file_of[name]), "pt") as sf:
            if rows is None:
                return sf.get_tensor(name)
            sl = sf.get_slice(name)
            return sl[: min(rows, sl.get_shape()[0])]


def is_adapter(path: str | Path) -> bool:
    p = Path(path)
    return p.is_dir() and (p / "adapter_config.json").exists()


# ---------------------------------------------------------------------------- base-model bank
def register_base(name: str, path: str | Path) -> None:
    _BANK[name] = Path(path)
    _fingerprint.cache_clear()


def _resolve_hf(model_id: str) -> Path | None:
    if Path(model_id).is_dir():
        return Path(model_id)
    try:
        from huggingface_hub import snapshot_download
        return Path(snapshot_download(model_id, allow_patterns=["*.safetensors", "*.json"],
                                      local_files_only=True))
    except Exception:
        return None


def bank() -> dict[str, Path]:
    if not _BANK and MODELS_YAML.exists():
        cfg = yaml.safe_load(MODELS_YAML.read_text()) or {}
        for ident in cfg.get("parent_bank", []):
            p = _resolve_hf(ident)
            if p is not None:
                _BANK[ident] = p
    return _BANK


# Tensors that identify a model family regardless of fine-tuning: token embeddings + first layers.
_FP_PATTERNS = [r"embed_tokens\.weight$", r"layers\.0\.self_attn\.[qkvo]_proj\.weight$",
                r"layers\.1\.self_attn\.[qkvo]_proj\.weight$"]


def _fp_names(src: TensorSource) -> list[str]:
    return sorted(n for n in src.names() if any(re.search(p, n) for p in _FP_PATTERNS))


@lru_cache(maxsize=32)
def _fingerprint(path: str) -> dict[str, np.ndarray]:
    src = TensorSource(path)
    out = {}
    for n in _fp_names(src):
        t = src.get(n, rows=EMBED_ROWS if "embed" in n else None)
        out[n] = t.float().flatten().numpy()
    return out


def _similarity(a: dict[str, np.ndarray], b: dict[str, np.ndarray]) -> float:
    """Mean per-tensor cosine over the identifying tensors. Shape mismatch or absence counts 0."""
    names = set(a) | set(b)
    if not names:
        return 0.0
    cos = []
    for n in names:
        x, y = a.get(n), b.get(n)
        if x is None or y is None or x.shape != y.shape:
            cos.append(0.0)
            continue
        d = np.linalg.norm(x) * np.linalg.norm(y)
        cos.append(float(x @ y / d) if d > 0 else 0.0)
    return float(np.mean(cos))


# ---------------------------------------------------------------------------- layer deltas
def _module_name(key: str) -> str | None:
    """'base_model.model.model.layers.0.self_attn.q_proj.lora_A.weight' -> 'model.layers.0.self_attn.q_proj'."""
    m = re.match(r"^(?:base_model\.model\.)?(.*)\.lora_[AB](?:\.[\w]+)?\.weight$", key)
    return m.group(1) if m else None


def _adapter_scale(path: Path) -> float:
    cfg = json.loads((path / "adapter_config.json").read_text())
    r, alpha = cfg["r"], cfg.get("lora_alpha", cfg["r"])
    return alpha / math.sqrt(r) if cfg.get("use_rslora") else alpha / r


def adapter_modules(path: str | Path) -> dict[str, tuple[str, str]]:
    """module -> (A key, B key)."""
    src = TensorSource(Path(path) / "adapter_model.safetensors")
    mods: dict[str, dict[str, str]] = {}
    for k in src.names():
        m = _module_name(k)
        if m:
            mods.setdefault(m, {})["A" if ".lora_A" in k else "B"] = k
    return {m: (v["A"], v["B"]) for m, v in mods.items() if "A" in v and "B" in v}


def lora_singular_values(A: torch.Tensor, B: torch.Tensor, scale: float) -> torch.Tensor:
    """Singular values of scale * B @ A without forming the (out x in) matrix."""
    qb, rb = torch.linalg.qr(B.float())
    qa, ra = torch.linalg.qr(A.float().T)
    return torch.linalg.svdvals(scale * (rb @ ra.T))


def delta_layers(model_path: str | Path, parent_path: str | Path | None = None) -> Iterator[tuple[str, torch.Tensor]]:
    """Yield (layer, singular values of delta-W) for every changed 2-D weight."""
    if is_adapter(model_path):
        scale = _adapter_scale(Path(model_path))
        src = TensorSource(Path(model_path) / "adapter_model.safetensors")
        for mod, (ka, kb) in sorted(adapter_modules(model_path).items()):
            yield mod, lora_singular_values(src.get(ka), src.get(kb), scale)
        return
    if parent_path is None:
        raise ValueError("full-model delta needs a parent")
    child, parent = TensorSource(model_path), TensorSource(parent_path)
    for name in sorted(child.names()):
        if name not in parent or child.shape(name) != parent.shape(name) or len(child.shape(name)) != 2:
            continue
        c, p = child.get(name), parent.get(name)
        if torch.equal(c, p):
            continue
        yield name.removesuffix(".weight"), torch.linalg.svdvals(c.float() - p.float())


def changed_layers(model_path: str | Path, parent_path: str | Path | None) -> list[str]:
    if is_adapter(model_path):
        return sorted(adapter_modules(model_path))
    if parent_path is None:
        return []
    child, parent = TensorSource(model_path), TensorSource(parent_path)
    out = []
    for name in sorted(child.names()):
        if name not in parent or child.shape(name) != parent.shape(name):
            out.append(name.removesuffix(".weight"))  # structurally new / reshaped
        elif not torch.equal(child.get(name), parent.get(name)):
            out.append(name.removesuffix(".weight"))
    return out


# ---------------------------------------------------------------------------- spectral metrics
def spectral_metrics(s: torch.Tensor) -> dict[str, float]:
    s = s.double()
    e = s ** 2
    tot = float(e.sum())
    if tot <= 0 or len(s) == 0:
        return {m: 0.0 for m in METRICS}
    p = e / tot
    nz = p[p > 0]
    h = float(-(nz * nz.log()).sum()) / math.log(len(s)) if len(s) > 1 else 0.0
    m2 = float(((s - s.mean()) ** 2).mean())
    kurt = float(((s - s.mean()) ** 4).mean() / m2 ** 2 - 3.0) if m2 > 0 and len(s) >= 4 else 0.0
    return {"energy_conc": float(e[:TOP_K].sum()) / tot, "kurtosis": kurt, "entropy": h,
            "frobenius": math.sqrt(tot), "top_sv": float(s[0])}


def aggregate(per_layer: dict[str, dict[str, float]]) -> dict[str, float]:
    feats = {}
    for m in METRICS:
        vals = [v[m] for v in per_layer.values()] or [0.0]
        feats[f"mean_{m}"] = float(np.mean(vals))
        feats[f"max_{m}"] = float(np.max(vals))
    return feats


def per_layer_metrics(model_path: str | Path, parent_path: str | Path | None = None) -> dict[str, dict[str, float]]:
    return {layer: spectral_metrics(s) for layer, s in delta_layers(model_path, parent_path)}


# ---------------------------------------------------------------------------- calibrated score
def load_calibration(path: Path = CALIBRATION) -> dict | None:
    return json.loads(path.read_text()) if path.exists() else None


def score_features(feats: dict[str, float], cal: dict) -> float:
    z = np.array([(feats[f] - cal["mean"][i]) / cal["std"][i] for i, f in enumerate(cal["features"])])
    logit = float(z @ np.array(cal["coef"]) + cal["intercept"])
    return 1.0 / (1.0 + math.exp(-logit))


# ---------------------------------------------------------------------------- operations
def identify_parent(model_path: str) -> ParentResponse:
    models = bank()
    if is_adapter(model_path):
        # A LoRA carries no base weights: the best we can do is shape-compatibility with each base.
        mods = adapter_modules(model_path)
        src = TensorSource(Path(model_path) / "adapter_model.safetensors")
        best, best_sim = None, 0.0
        for name, bpath in models.items():
            bsrc = TensorSource(bpath)
            ok = tot = 0
            for mod, (ka, kb) in mods.items():
                tot += 1
                wn = f"{mod}.weight"
                if wn in bsrc and bsrc.shape(wn) == (src.shape(kb)[0], src.shape(ka)[1]):
                    ok += 1
            sim = ok / tot if tot else 0.0
            if sim > best_sim:
                best, best_sim = name, sim
        return ParentResponse(parent=best if best_sim >= PARENT_THRESHOLD else None,
                              similarity=round(best_sim, 4), changed_layers=sorted(mods))
    fp = _fingerprint(str(model_path))
    best, best_sim = None, -1.0
    for name, bpath in models.items():
        sim = _similarity(fp, _fingerprint(str(bpath)))
        if sim > best_sim:
            best, best_sim = name, sim
    parent = best if best_sim >= PARENT_THRESHOLD else None
    layers = changed_layers(model_path, models[parent]) if parent else []
    return ParentResponse(parent=parent, similarity=round(max(best_sim, 0.0), 4), changed_layers=layers)


MIN_CALIBRATED_DIM = 64  # smaller layers (toy and test models) are outside what the logistic regression was fitted on


def spectral_score(model_path: str, parent: str) -> SpectralResponse:
    cal = load_calibration()
    if cal is None:
        raise RuntimeError("weight-space model not calibrated (run gpu_worker.calibrate_weightspace)")
    parent_path = bank().get(parent) or (Path(parent) if Path(parent).is_dir() else None)
    per_layer = per_layer_metrics(model_path, parent_path)
    if not per_layer:
        return SpectralResponse(score=0.0, per_layer={})
    if not is_adapter(model_path):  # an adapter's update is B @ A over the base layer's full size: always in range
        src = TensorSource(model_path)
        dims = [min(src.shape(n + ".weight")) for n in per_layer if n + ".weight" in src]
        if dims and max(dims) < MIN_CALIBRATED_DIM:
            raise ValueError(f"outside the calibrated range: every changed layer is smaller than {MIN_CALIBRATED_DIM} in some dimension; "
                             "the detector was calibrated on LoRA updates of real language models")
    return SpectralResponse(score=round(score_features(aggregate(per_layer), cal), 4), per_layer=per_layer)


@router.post("/weights/parent", response_model=ParentResponse)
def weights_parent(req: ParentRequest) -> ParentResponse:
    try:
        return identify_parent(req.model_path)
    except FileNotFoundError as e:
        raise HTTPException(404, str(e))


@router.post("/weights/spectral", response_model=SpectralResponse)
def weights_spectral(req: SpectralRequest) -> SpectralResponse:
    try:
        return spectral_score(req.model_path, req.parent)
    except FileNotFoundError as e:
        raise HTTPException(404, str(e))
    except ValueError as e:  # outside the calibrated range: refuse rather than return a meaningless score
        raise HTTPException(422, str(e))
    except RuntimeError as e:
        raise HTTPException(503, str(e))
