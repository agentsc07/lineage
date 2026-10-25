"""Hermetic tests for gpu_worker.weights_api using tiny synthetic models."""
import json

import torch
from safetensors.torch import save_file

from gpu_worker import weights_api as w

H, V = 32, 64


def _base(seed: int) -> dict[str, torch.Tensor]:
    g = torch.Generator().manual_seed(seed)
    t = {"model.embed_tokens.weight": torch.randn(V, H, generator=g)}
    for i in range(3):
        for p in "qkvo":
            t[f"model.layers.{i}.self_attn.{p}_proj.weight"] = torch.randn(H, H, generator=g)
    return t


def _save(d, tensors):
    d.mkdir(parents=True, exist_ok=True)
    save_file(tensors, str(d / "model.safetensors"))
    return d


def test_parent_and_changed_layers(tmp_path):
    a, b = _base(1), _base(2)
    pa, pb = _save(tmp_path / "a", a), _save(tmp_path / "b", b)
    child = dict(a)
    child["model.layers.2.self_attn.q_proj.weight"] = a["model.layers.2.self_attn.q_proj.weight"] + 0.01
    pc = _save(tmp_path / "child", child)
    w._BANK.clear()
    w.register_base("base-a", pa)
    w.register_base("base-b", pb)
    r = w.identify_parent(str(pc))
    assert r.parent == "base-a" and r.similarity > 0.99
    assert r.changed_layers == ["model.layers.2.self_attn.q_proj"]
    stranger = _save(tmp_path / "s", _base(3))
    assert w.identify_parent(str(stranger)).parent is None
    w._BANK.clear()


def test_lora_svals_match_dense():
    A, B = torch.randn(4, H), torch.randn(H, 4)
    fast = w.lora_singular_values(A, B, 2.0)
    dense = torch.linalg.svdvals(2.0 * B @ A)[:4]
    assert torch.allclose(fast, dense, atol=1e-3)


def test_spectral_metrics_rank_one_is_concentrated():
    m = w.spectral_metrics(torch.tensor([5.0, 0.0, 0.0, 0.0]))
    assert abs(m["energy_conc"] - 1.0) < 1e-9 and m["entropy"] == 0.0 and m["top_sv"] == 5.0
    flat = w.spectral_metrics(torch.ones(8))
    assert abs(flat["entropy"] - 1.0) < 1e-9


def test_adapter_layers_and_score(tmp_path):
    d = tmp_path / "ad"
    d.mkdir()
    k = "base_model.model.model.layers.0.self_attn.q_proj"
    save_file({f"{k}.lora_A.weight": torch.randn(4, H), f"{k}.lora_B.weight": torch.randn(H, 4)},
              str(d / "adapter_model.safetensors"))
    (d / "adapter_config.json").write_text(json.dumps({"r": 4, "lora_alpha": 8}))
    assert w.changed_layers(d, None) == ["model.layers.0.self_attn.q_proj"]
    pl = w.per_layer_metrics(d)
    feats = w.aggregate(pl)
    cal = {"features": w.FEATURES, "mean": [0.0] * len(w.FEATURES), "std": [1.0] * len(w.FEATURES),
           "coef": [0.0] * len(w.FEATURES), "intercept": 0.0}
    assert w.score_features(feats, cal) == 0.5
