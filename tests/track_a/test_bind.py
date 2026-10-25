import sys
import types
import zipfile

import pytest

import lineage
from lineage.bind import LoadRefused, check, find_pickle_files, load
from lineage.passport.build import build_passport
from lineage.schemas.policy import PolicyPack
from lineage.schemas.passport import SourceRef
from lineage.signing.ed25519 import sign_passport
from lineage.signing.keys import generate_keypair, load_private_key, load_public_key


@pytest.fixture
def policy(policy_path):
    return PolicyPack.from_yaml(policy_path)


@pytest.fixture
def keys(tmp_path):
    generate_keypair(tmp_path / "k")
    return load_private_key(tmp_path / "k/default.key"), load_public_key(tmp_path / "k/default.pub")


@pytest.fixture
def model(tiny_model):
    (tiny_model / "tokenizer.json").write_text('{"v": 1}')
    return tiny_model


@pytest.fixture
def signed(model, keys):
    return sign_passport(build_passport(model, "model", "t", "1", SourceRef(), trust_level="inspected"), keys[0], "k")


def test_clean_artifact_passes(model, signed, policy):
    assert check(model, signed, policy) == []


def test_swapped_tokenizer_refused(model, signed, policy):
    (model / "tokenizer.json").write_text('{"v": 2, "added_tokens": ["<evil>"]}')
    problems = check(model, signed, policy)
    assert any("tokenizer.json" in p for p in problems)
    with pytest.raises(LoadRefused, match="tokenizer.json"):
        load(model, signed, policy)


def test_modified_weights_refused(model, signed, policy, tiny_model_child):
    (model / "model.safetensors").write_bytes((tiny_model_child / "model.safetensors").read_bytes())
    with pytest.raises(LoadRefused, match="model.safetensors"):
        load(model, signed, policy)


def test_unpinned_file_refused(model, signed, policy):
    (model / "modeling_evil.py").write_text("x = 1")
    with pytest.raises(LoadRefused, match="unpinned.*modeling_evil.py"):
        load(model, signed, policy)


def _torch_zip(path):
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("archive/data.pkl", b"\x80\x02N.")


def test_pickle_refused_by_policy_even_if_pinned(model, keys, policy):
    _torch_zip(model / "weights.pt")
    (model / "legacy.bin").write_bytes(b"\x80\x04N.")
    signed = sign_passport(build_passport(model, "model", "t", "1", SourceRef()), keys[0], "k")
    assert {p.name for p in find_pickle_files(model)} == {"weights.pt", "legacy.bin"}
    problems = check(model, signed, policy)
    assert any("pickle" in p and "weights.pt" in p for p in problems)
    assert any("pickle" in p and "legacy.bin" in p for p in problems)
    policy.model_files.allow_pickle = True
    assert check(model, signed, policy) == []


def test_safetensors_bin_not_flagged(model):
    (model / "pytorch_model.bin").write_bytes(b"not a pickle")
    assert find_pickle_files(model) == []


def test_no_policy_defaults_to_refusing_pickle(model, keys):
    (model / "w.pkl").write_bytes(b"\x80\x04N.")
    signed = sign_passport(build_passport(model, "model", "t", "1", SourceRef()), keys[0], "k")
    assert any("pickle" in p for p in check(model, signed, None))


def test_no_passport_refused(model, policy):
    with pytest.raises(LoadRefused, match="no passport"):
        load(model, None, policy)


def test_passport_autodiscovered_next_to_artifact(model, signed, policy):
    (model / "passport.json").write_text(signed.model_dump_json(by_alias=True))
    with pytest.raises(LoadRefused, match="unpinned"):  # passport.json itself isn't pinned...
        load(model, None, policy)
    side = model.parent / (model.name + ".passport.json")
    side.write_text(signed.model_dump_json(by_alias=True))
    (model / "passport.json").unlink()
    tensors = load(model, None, policy)
    assert "layers.0.weight" in tensors


def test_signature_checked_when_key_given(model, signed, policy, tmp_path):
    generate_keypair(tmp_path / "other")
    other = load_public_key(tmp_path / "other/default.pub")
    with pytest.raises(LoadRefused, match="signature"):
        load(model, signed, policy, public_key=other)


def test_load_returns_tensors(model, signed, policy, keys):
    out = load(model, signed, policy, public_key=keys[1])
    assert set(out) == {"layers.0.weight", "layers.0.bias", "layers.1.weight", "layers.1.bias"}


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


def test_transformers_wrapper_verifies_then_delegates(model, signed, policy, fake_transformers):
    from lineage.bind import LineageAutoModel

    out = LineageAutoModel.from_pretrained(model, passport=signed, policy=policy)
    assert out == "MODEL"
    path, kw = fake_transformers[0]
    assert path == str(model) and kw["use_safetensors"] is True
    (model / "tokenizer.json").write_text("{}")
    with pytest.raises(LoadRefused):
        LineageAutoModel.from_pretrained(model, passport=signed, policy=policy)
    assert len(fake_transformers) == 1  # never reached transformers


def test_load_uses_transformers_when_available(model, signed, policy, fake_transformers):
    assert load(model, signed, policy, dtype="bf16") == "MODEL"
    assert fake_transformers[0][1]["dtype"] == "bf16"


def test_trust_remote_code_needs_inspected_trust(model, keys, policy, fake_transformers):
    declared = sign_passport(build_passport(model, "model", "t", "1", SourceRef(), trust_level="declared"), keys[0], "k")
    with pytest.raises(LoadRefused, match="trust_remote_code"):
        load(model, declared, policy, trust_remote_code=True)
