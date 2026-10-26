import json
import os

from lineage.inspect import model_config, model_pickle
from tests.fixtures.builders import MARKER, make_benign_pickle, make_malicious_pickle, make_torch_zip


def by_id(fs):
    return {f.id: f for f in fs}


def test_safetensors_model_is_clean(tiny_model):
    assert model_pickle.scan(tiny_model) == []
    assert model_config.scan(tiny_model) == []


def test_malicious_pickle_all_protocols(tmp_path):
    for proto in (0, 2, 4):
        p = make_malicious_pickle(tmp_path / f"m{proto}.pkl", proto)
        fs = by_id(model_pickle.scan(p))
        f = fs["MODEL.PICKLE.DANGEROUS_GLOBAL"]
        assert f.severity == "critical", proto
        assert f.evidence[0].detail.startswith(("STACK_GLOBAL", "GLOBAL"))
        assert "system" in f.title and "lineage_marker_pickle" in f.evidence[0].detail
        assert "MODEL.PICKLE.PRESENT" in fs
    assert not os.path.exists(MARKER + "pickle")  # scanning must never execute the payload


def test_benign_pickle_only_notes_the_format(tmp_path):
    fs = model_pickle.scan(make_benign_pickle(tmp_path / "ok.pkl"))
    assert [f.id for f in fs] == ["MODEL.PICKLE.PRESENT"]


def test_torch_zip_and_directory(tmp_path):
    z = make_torch_zip(tmp_path / "model" / "pytorch_model.bin", make_malicious_pickle(tmp_path / "x.pkl"))
    fs = model_pickle.scan(tmp_path / "model")
    bad = [f for f in fs if f.id == "MODEL.PICKLE.DANGEROUS_GLOBAL"]
    assert bad and "pytorch_model.bin!archive/data.pkl" in bad[0].evidence[0].ref
    assert z.exists()


def test_non_pickle_bin_is_ignored(tmp_path):
    (tmp_path / "weights.bin").write_bytes(b"GGUF" + b"\x00" * 64)
    assert model_pickle.scan(tmp_path) == []


def test_mangled_pickle_is_suspicious(tmp_path):
    p = tmp_path / "bad.pkl"
    p.write_bytes(b"\x80\x04\x95\xff\xff\xff\xff\xff")
    assert by_id(model_pickle.scan(p))["MODEL.PICKLE.UNPARSEABLE"].severity == "medium"


def test_config_remote_code(tiny_model):
    (tiny_model / "config.json").write_text(json.dumps({
        "model_type": "tiny", "trust_remote_code": True,
        "auto_map": {"AutoModel": "modeling_tiny.TinyModel", "AutoConfig": "other-org/repo--cfg.Cfg"},
    }))
    (tiny_model / "modeling_tiny.py").write_text("import subprocess\nsubprocess.run(['true'])\n")
    fs = by_id(model_config.scan(tiny_model))
    assert fs["MODEL.CONFIG.TRUST_REMOTE_CODE"].severity == "high"
    assert fs["MODEL.CONFIG.AUTO_MAP"].evidence[0].ref == "config.json#auto_map"
    assert "MODEL.CONFIG.EXTERNAL_CODE" in fs and "MODEL.CONFIG.CUSTOM_CODE" in fs
    assert "PKG.SIGNAL.SUBPROCESS" in fs  # the custom code goes through the package pipeline
    assert [p.name for p in model_config.remote_code_files(tiny_model)] == ["modeling_tiny.py"]
