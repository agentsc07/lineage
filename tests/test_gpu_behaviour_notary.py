"""Hermetic tests for behaviour/notary helpers (no GPU, no network)."""
import json

import pytest
import torch
from fastapi import HTTPException

from gpu_worker import behaviour_api as b
from gpu_worker import modelio
from gpu_worker import notary_api as n
from lineage.schemas.gpu import NotaryCertificate


def test_js_divergence_bounds():
    p = torch.tensor([[1.0, 0.0], [0.5, 0.5]])
    assert float(b._js(p, p).max()) < 1e-6
    q = torch.tensor([[0.0, 1.0], [0.5, 0.5]])
    js = b._js(p, q)
    assert abs(float(js[0]) - 1.0) < 1e-3 and float(js[1]) < 1e-6


def test_refusal_regex():
    assert b.REFUSAL.search("I'm sorry, but I can't help with that")
    assert not b.REFUSAL.search("Sure, here is how")


def test_default_probes_have_safety_and_general():
    cats = {p["category"] for p in b.load_probes("default")}
    assert cats == {"general", "safety"}
    with pytest.raises(HTTPException):
        b.load_probes("does-not-exist")


def test_gpu_endpoints_503_without_gpu(monkeypatch):
    monkeypatch.setattr(modelio, "have_gpu", lambda: False)
    with pytest.raises(HTTPException) as e:
        b._need_gpu()
    assert e.value.status_code == 503
    with pytest.raises(HTTPException) as e:
        n._need_gpu()
    assert e.value.status_code == 503


def test_notary_signature_roundtrip_and_tamper(tmp_path, monkeypatch):
    monkeypatch.setattr(n, "DATA", tmp_path)
    (tmp_path / "hidden.json").write_text(json.dumps([{"ctx": "a", "choices": [" b"], "gold": 0}]))
    sig = n._key().sign(n._canon({"cert_id": "nc-1", "model_digest": "d", "fingerprint": "f"})).hex()
    cert = NotaryCertificate(cert_id="nc-1", model_digest="d", fingerprint="f", signature=sig)
    assert n.verify_certificate(cert)
    assert not n.verify_certificate(cert.model_copy(update={"fingerprint": "tampered"}))
    assert n.commitment() == n.commitment() and len(n.commitment()) == 64


def test_notary_check_unknown_and_path_traversal(tmp_path, monkeypatch):
    monkeypatch.setattr(n, "DATA", tmp_path)
    assert not n.check_impl("x", "nc-missing").match
    assert not n.check_impl("x", "../../etc/passwd").match
