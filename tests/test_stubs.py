"""Every stub module imports and its public functions raise NotImplementedError until its track lands."""
import importlib
import inspect
import pkgutil

import pytest

import gpu_worker
import lineage
import lineage_server
import mcp_gateway

SKIP = {"lineage.schemas", "lineage.cli", "lineage_server.app", "lineage_server.mock", "lineage_server.routes"}


def _modules():
    for pkg in (lineage, lineage_server, mcp_gateway, gpu_worker):
        for m in pkgutil.walk_packages(pkg.__path__, pkg.__name__ + "."):
            if not any(m.name == s or m.name.startswith(s + ".") for s in SKIP):
                yield m.name


@pytest.mark.parametrize("name", sorted(_modules()))
def test_module_imports(name):
    importlib.import_module(name)


def test_stub_raises():
    from lineage.risk import risk_score

    with pytest.raises(NotImplementedError):
        risk_score([], "unknown")
    assert inspect.signature(risk_score).return_annotation in (int, "int")
