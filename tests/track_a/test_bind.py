"""lineage.load() trusts only a registry-signed attestation for this environment (REFACTOR_SPEC section 5); see also
tests/test_load_enforcement.py for the end-to-end refusals."""
import sys
import types
import zipfile
from datetime import timedelta

import pytest

import lineage
from lineage.bind import LoadRefused, find_pickle_files, load
from lineage.client import check_for_use
from tests.attest_helpers import REGISTRY_PUB, attest

KW = dict(registry_pubkey=REGISTRY_PUB, server="", env="dev")


@pytest.fixture
def model(tiny_model):
    (tiny_model / "tokenizer.json").write_text('{"v": 1}')
    return tiny_model


@pytest.fixture
def no_transformers(monkeypatch):
    # a None entry makes `import transformers` raise ImportError, exercising the raw-safetensors fallback
    monkeypatch.setitem(sys.modules, "transformers", None)


def test_clean_artifact_passes(model):
    attest(model)
    assert check_for_use(model, **KW) == []


def test_swapped_tokenizer_refused(model):
    attest(model)
    (model / "tokenizer.json").write_text('{"v": 2, "added_tokens": ["<evil>"]}')
    assert any("tokenizer.json" in p for p in check_for_use(model, **KW))
    with pytest.raises(LoadRefused, match="tokenizer.json"):
        load(model, **KW)


def test_modified_weights_refused(model, tiny_model_child):
    attest(model)
    (model / "model.safetensors").write_bytes((tiny_model_child / "model.safetensors").read_bytes())
    with pytest.raises(LoadRefused, match="model.safetensors"):
        load(model, **KW)


def test_unattested_file_refused(model):
    attest(model)
    (model / "modeling_evil.py").write_text("x = 1")
    with pytest.raises(LoadRefused, match="unattested file: modeling_evil.py"):
        load(model, **KW)


def test_missing_file_refused(model):
    attest(model)
    (model / "tokenizer.json").unlink()
    with pytest.raises(LoadRefused, match="missing file: tokenizer.json"):
        load(model, **KW)


def _torch_zip(path):
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("archive/data.pkl", b"\x80\x02N.")


def test_pickle_refused_even_if_attested(model):
    _torch_zip(model / "weights.pt")
    (model / "legacy.bin").write_bytes(b"\x80\x04N.")
    attest(model)
    assert {p.name for p in find_pickle_files(model)} == {"weights.pt", "legacy.bin"}
    problems = check_for_use(model, **KW)
    assert any("pickle" in p and "weights.pt" in p for p in problems) and any("legacy.bin" in p for p in problems)
    assert check_for_use(model, allow_pickle=True, **KW) == []


def test_safetensors_bin_not_flagged(model):
    (model / "pytorch_model.bin").write_bytes(b"not a pickle")
    assert find_pickle_files(model) == []


def test_no_attestation_refused(model):
    with pytest.raises(LoadRefused, match="no attestation"):
        load(model, **KW)


def test_no_pinned_registry_key_refused(model):
    attest(model)
    with pytest.raises(LoadRefused, match="no registry public key"):
        load(model, server="", env="dev", registry_pubkey=None)


def test_attestation_signed_by_another_key_refused(model):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    attest(model, key=Ed25519PrivateKey.generate())
    with pytest.raises(LoadRefused, match="signature does not verify"):
        load(model, **KW)


def test_load_returns_tensors(model, no_transformers):
    attest(model)
    assert set(load(model, **KW)) == {"layers.0.weight", "layers.0.bias", "layers.1.weight", "layers.1.bias"}


def test_lineage_load_exported():
    assert lineage.load is load and lineage.LoadRefused is LoadRefused


@pytest.fixture
def fake_transformers(monkeypatch):
    calls = []
    mod = types.ModuleType("transformers")

    class _Auto:
        @classmethod
        def from_pretrained(cls, path, **kw):
            calls.append((str(path), kw))
            return "MODEL"

    mod.AutoModelForCausalLM = _Auto
    mod.AutoModel = _Auto
    monkeypatch.setitem(sys.modules, "transformers", mod)
    return calls


def test_transformers_wrapper_verifies_then_delegates(model, fake_transformers):
    from lineage.bind import LineageAutoModel

    attest(model)
    assert LineageAutoModel.from_pretrained(model, **KW) == "MODEL"
    path, kw = fake_transformers[0]
    assert path == str(model) and kw["use_safetensors"] is True
    (model / "tokenizer.json").write_text("{}")
    with pytest.raises(LoadRefused):
        LineageAutoModel.from_pretrained(model, **KW)
    assert len(fake_transformers) == 1  # never reached transformers


def test_load_uses_transformers_when_available(model, fake_transformers):
    attest(model)
    assert load(model, dtype="bf16", **KW) == "MODEL"
    assert fake_transformers[0][1]["dtype"] == "bf16"


def test_trust_remote_code_needs_origin_verified_trust(model, fake_transformers):
    attest(model, trust="unknown")
    with pytest.raises(LoadRefused, match="trust_remote_code"):
        load(model, trust_remote_code=True, **KW)
    attest(model, trust="origin_verified")
    assert load(model, trust_remote_code=True, **KW) == "MODEL"
