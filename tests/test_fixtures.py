import csv
import json

from safetensors import safe_open


def test_tiny_model_has_two_layers(tiny_model):
    with safe_open(str(tiny_model / "model.safetensors"), "np") as f:
        assert sorted(f.keys()) == ["layers.0.bias", "layers.0.weight", "layers.1.bias", "layers.1.weight"]


def test_child_differs_only_in_one_tensor(tiny_model, tiny_model_child):
    with safe_open(str(tiny_model / "model.safetensors"), "np") as a, safe_open(str(tiny_model_child / "model.safetensors"), "np") as b:
        changed = [k for k in a.keys() if (a.get_tensor(k) != b.get_tensor(k)).any()]
    assert changed == ["layers.1.weight"]


def test_tiny_model_is_deterministic(tmp_path):
    from tests.fixtures.builders import make_tiny_model
    a = make_tiny_model(tmp_path / "a")
    b = make_tiny_model(tmp_path / "b")
    assert (a / "model.safetensors").read_bytes() == (b / "model.safetensors").read_bytes()


def test_dataset(tiny_dataset):
    rows = list(csv.DictReader(tiny_dataset.open()))
    assert len(rows) == 20 and set(rows[0]) == {"id", "text", "label"}


def test_package_and_tool(toy_package, toy_tool):
    assert (toy_package / "toypkg" / "core.py").exists()
    manifest = json.loads((toy_tool / "manifest.json").read_text())
    assert {"name", "description", "inputSchema", "permissions"} <= set(manifest)
