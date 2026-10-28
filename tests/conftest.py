from pathlib import Path

import pytest

from tests.fixtures.builders import make_tiny_model

FIXTURES = Path(__file__).parent / "fixtures"
REPO = Path(__file__).parent.parent


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    """Tests never call the real OSV API (it is slow, and its answers change over time)."""
    monkeypatch.setenv("LINEAGE_OFFLINE", "1")


@pytest.fixture(autouse=True)
def dev_server_defaults(monkeypatch):
    """Server tests run unauthenticated with local paths allowed unless a test turns auth on (tests/test_roles.py)."""
    monkeypatch.setenv("LINEAGE_REQUIRE_AUTH", "0")
    monkeypatch.setenv("LINEAGE_MONITOR_MINUTES", "0")  # tests tick by hand
    monkeypatch.setenv("LINEAGE_DEV_LOCAL_PATHS", "1")


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


# The GPU worker's modules import torch at the top, which only the Brev machine has. Without it those test files are not collected (a skip
# marker cannot help: the import fails first). `uv run pytest -q` therefore stays green on a laptop without torch; the full run is on Brev.
import importlib.util as _ilu

collect_ignore_glob = ["test_gpu_*.py"] if _ilu.find_spec("torch") is None else []
