"""R4.4: parent identification against a hub base model by HTTP range requests, without downloading the base."""
import json

import numpy as np
import pytest
from fastapi.testclient import TestClient
from safetensors.numpy import save_file

from lineage.diff import hub_parent as hp
from lineage.intake.hub import HttpHub
from lineage.intake.pipeline import run_to_decision
from lineage.schemas.policy import PolicyPack
from tests.fakehub import create_app
from tests.server_helpers import NOW


def model(path, seed, *, tokens=None, vocab=2000, hidden=64, noise_of=None, noise=0.0):
    path.mkdir(parents=True, exist_ok=True)
    emb = np.random.default_rng(seed).standard_normal((vocab, hidden)).astype(np.float32)
    if noise_of is not None:
        emb = noise_of + noise * np.random.default_rng(seed + 1).standard_normal(noise_of.shape).astype(np.float32)
    save_file({"model.embed_tokens.weight": emb, "layers.0.weight": np.ones((4, 4), np.float32)}, str(path / "model.safetensors"))
    (path / "config.json").write_text(json.dumps({"hidden_size": hidden, "vocab_size": vocab, "num_hidden_layers": 1}))
    (path / "tokenizer.json").write_text(json.dumps({"model": {"vocab": {"a": 0, "b": 1}, "merges": []},
                                                     "added_tokens": [{"id": 2, "content": "<|im_end|>", "special": True}]}))
    return emb


@pytest.fixture
def hubs(tmp_path):
    root = tmp_path / "hub"
    base_emb = model(root / "models" / "org" / "base", 1)
    app = create_app(root, {"hf:org/base": {"released_at": "2025-01-01T00:00:00Z"}})
    return root, base_emb, HttpHub(base_url="http://testserver", client=TestClient(app), trusted_local=False)


def test_a_fine_tune_matches_its_base_and_only_a_sliver_is_fetched(hubs, tmp_path):
    root, base_emb, hub = hubs
    child = tmp_path / "child"
    model(child, 5, noise_of=base_emb, noise=0.05)
    m = hp.compare(child, "org/base", "main", base_url="http://testserver", client=hub.client, work_dir=tmp_path / "w")
    assert m.similarity > 0.95 and m.tensor == "model.embed_tokens.weight"
    full = (root / "models" / "org" / "base" / "model.safetensors").stat().st_size
    assert m.bytes_fetched < full  # config + header + 512 of 2000 embedding rows, not the whole file
    assert (tmp_path / "w" / "tokenizer.json").exists()


def test_an_unrelated_model_does_not_match(hubs, tmp_path):
    _, _, hub = hubs
    child = tmp_path / "other"
    model(child, 99)
    m = hp.compare(child, "org/base", "main", base_url="http://testserver", client=hub.client)
    assert abs(m.similarity) < 0.2


def test_a_different_architecture_is_excluded_from_config_alone(hubs, tmp_path):
    _, _, hub = hubs
    child = tmp_path / "wide"
    model(child, 3, hidden=32)
    m = hp.compare(child, "org/base", "main", base_url="http://testserver", client=hub.client)
    assert m.similarity == 0.0 and "hidden_size" in m.notes[0] and m.tensor is None


def run(child, base, hub, policy_path):
    return run_to_decision("model", str(child), "dev", PolicyPack.from_yaml(policy_path), "j", now=NOW, hub=hub, claims={"base_model": base})[0]


def test_pipeline_identifies_the_claimed_base_and_diffs_its_tokenizer(hubs, tmp_path, policy_path):
    _, base_emb, hub = hubs
    child = tmp_path / "child"
    model(child, 5, noise_of=base_emb, noise=0.05)
    (child / "tokenizer.json").write_text(json.dumps({"model": {"vocab": {"a": 0, "b": 1}, "merges": []},
                                                      "added_tokens": [{"id": 2, "content": "<|im_end|>", "special": False}]}))  # a flipped special flag
    d = run(child, "org/base", hub, policy_path)
    got = {f.id for f in d.findings}
    assert "MODEL.PARENT.IDENTIFIED" in got and "MODEL.TOKENIZER.SPECIAL_FLAG_CHANGED" in got


def test_pipeline_flags_a_base_the_weights_contradict(hubs, tmp_path, policy_path):
    _, _, hub = hubs
    child = tmp_path / "liar"
    model(child, 77)
    d = run(child, "org/base", hub, policy_path)
    f = next(f for f in d.findings if f.id == "MODEL.PARENT.CLAIM_MISMATCH")
    assert f.severity == "high" and "only declared" in f.title


def test_unreachable_hub_is_a_not_run(tmp_path, policy_path):
    child = tmp_path / "c"
    model(child, 1)
    d = run(child, "org/base", HttpHub(base_url="http://127.0.0.1:9", trusted_local=False), policy_path)
    assert "CHECK.NOT_RUN.PARENT_FETCH" in {f.id for f in d.findings}
