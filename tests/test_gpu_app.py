"""GPU worker app: wiring, 503 fallbacks and the weights endpoints through HTTP (no GPU needed)."""
import pytest
import pytest
torch = pytest.importorskip("torch")
from fastapi.testclient import TestClient
from safetensors.torch import save_file

from gpu_worker import modelio
from gpu_worker import weights_api as w
from gpu_worker.app import app

client = TestClient(app)


def test_health_lists_endpoints():
    r = client.get("/health").json()
    assert r["status"] == "ok" and "/weights/parent" in r["endpoints"] and "/review/code" in r["endpoints"]


def test_reviewer_is_503_until_configured():
    r = client.post("/review/card", json={"card_text": "x", "measured": {}})
    assert r.status_code == 503 and "reviewer" in r.json()["detail"]
    r = client.post("/review/code", json={"purpose": "p", "slices": []})
    assert r.status_code == 503


def test_gpu_endpoints_503_without_gpu(monkeypatch):
    monkeypatch.setattr(modelio, "have_gpu", lambda: False)
    for path, body in [("/behaviour/diff", {"child": "a", "parent": "b", "probe_set": "default"}),
                       ("/behaviour/claims", {"model": "a", "claims": []}),
                       ("/notary/certify", {"model_path": "a"}),
                       ("/notary/check", {"model_path": "a", "cert_id": "nc-1"})]:
        assert client.post(path, json=body).status_code == 503, path


def test_weights_parent_over_http(tmp_path):
    g = torch.Generator().manual_seed(1)
    t = {"model.embed_tokens.weight": torch.randn(16, 8, generator=g),
         "model.layers.0.self_attn.q_proj.weight": torch.randn(8, 8, generator=g)}
    (tmp_path / "base").mkdir()
    save_file(t, str(tmp_path / "base" / "model.safetensors"))
    child = dict(t)
    child["model.layers.0.self_attn.q_proj.weight"] = t["model.layers.0.self_attn.q_proj.weight"] + 0.1
    (tmp_path / "child").mkdir()
    save_file(child, str(tmp_path / "child" / "model.safetensors"))
    w._BANK.clear()
    w.register_base("toy", tmp_path / "base")
    try:
        r = client.post("/weights/parent", json={"model_path": str(tmp_path / "child")})
        assert r.status_code == 200 and r.json()["parent"] == "toy"
        assert r.json()["changed_layers"] == ["model.layers.0.self_attn.q_proj"]
        assert client.post("/weights/parent", json={"model_path": str(tmp_path / "nope")}).status_code == 404
    finally:
        w._BANK.clear()
