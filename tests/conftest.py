from pathlib import Path

import pytest

from tests.fixtures.builders import make_tiny_model

FIXTURES = Path(__file__).parent / "fixtures"
REPO = Path(__file__).parent.parent


@pytest.fixture
def policy_path() -> Path:
    return REPO / "examples" / "policy.org.yaml"


@pytest.fixture
def tiny_model(tmp_path: Path) -> Path:
    """Directory with a 2-layer model.safetensors and config.json."""
    return make_tiny_model(tmp_path / "tiny_model")


@pytest.fixture
def tiny_model_child(tmp_path: Path) -> Path:
    """Same weights as `tiny_model` except layers.1.weight is changed."""
    return make_tiny_model(tmp_path / "tiny_model_child", perturb="layers.1.weight")


@pytest.fixture
def tiny_dataset() -> Path:
    """CSV with 20 rows: id,text,label."""
    return FIXTURES / "tiny_dataset.csv"


@pytest.fixture
def toy_package() -> Path:
    """Benign pip-style package directory."""
    return FIXTURES / "toy_package"


@pytest.fixture
def toy_tool() -> Path:
    """Benign MCP tool: manifest.json + server.py."""
    return FIXTURES / "toy_tool"
