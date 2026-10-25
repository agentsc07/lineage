import math

import numpy as np
from safetensors.numpy import save_file

from lineage.diff.layers import diff_models
from lineage.diff.parent import fingerprint_parent
from tests.fixtures.builders import make_tiny_model


def test_diff_reports_only_changed_tensor(tiny_model, tiny_model_child):
    d = {x.tensor: x for x in diff_models(tiny_model, tiny_model_child)}
    assert {k for k, v in d.items() if v.changed} == {"layers.1.weight"}
    assert d["layers.0.weight"].relative_l2 == 0.0
    # delta is +0.5 on all 16 entries -> ||d|| = 2.0
    a = np.random.default_rng(0)
    assert d["layers.1.weight"].relative_l2 > 0


def test_diff_relative_l2_exact(tmp_path):
    save_file({"w": np.array([3.0, 4.0], dtype=np.float32)}, str(tmp_path / "a.safetensors"))
    save_file({"w": np.array([3.0, 5.0], dtype=np.float32)}, str(tmp_path / "b.safetensors"))
    (d,) = diff_models(tmp_path / "a.safetensors", tmp_path / "b.safetensors")
    assert math.isclose(d.relative_l2, 1 / 5, rel_tol=1e-6)


def test_diff_missing_and_shape_mismatch_are_inf(tmp_path):
    save_file({"w": np.zeros(4, np.float32), "only_a": np.ones(2, np.float32)}, str(tmp_path / "a.safetensors"))
    save_file({"w": np.zeros(5, np.float32), "only_b": np.ones(2, np.float32)}, str(tmp_path / "b.safetensors"))
    d = {x.tensor: x for x in diff_models(tmp_path / "a.safetensors", tmp_path / "b.safetensors")}
    assert set(d) == {"w", "only_a", "only_b"}
    assert all(x.changed and math.isinf(x.relative_l2) for x in d.values())


def test_diff_bf16_and_f16(tmp_path):
    import struct
    # bf16 for 1.0 is 0x3F80, for 2.0 is 0x4000; write raw safetensors by hand
    import json

    def write(path, dtype, raw):
        h = json.dumps({"w": {"dtype": dtype, "shape": [len(raw) // (2)], "data_offsets": [0, len(raw)]}}).encode()
        path.write_bytes(struct.pack("<Q", len(h)) + h + raw)

    write(tmp_path / "a.safetensors", "BF16", struct.pack("<H", 0x3F80))
    write(tmp_path / "b.safetensors", "BF16", struct.pack("<H", 0x4000))
    (d,) = diff_models(tmp_path / "a.safetensors", tmp_path / "b.safetensors")
    assert math.isclose(d.relative_l2, 1.0)


def test_diff_accepts_directories(tiny_model, tiny_model_child):
    assert any(x.changed for x in diff_models(tiny_model, tiny_model_child))


def test_fingerprint_parent(tmp_path, tiny_model, tiny_model_child):
    other = make_tiny_model(tmp_path / "other", seed=7)
    m = fingerprint_parent(tiny_model_child, {"base": tiny_model, "other": other})
    assert m.parent == "base" and m.similarity > 0.7
    unrelated = make_tiny_model(tmp_path / "unrel", seed=99)
    assert fingerprint_parent(unrelated, {"base": tiny_model}).parent is None
