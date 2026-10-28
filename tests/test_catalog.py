"""Every finding id the code can emit is explained by the catalogue, and every catalogue entry points at real code."""
import importlib
import re
from pathlib import Path

from lineage.catalog import CHECKERS, checker_for, plain_name

ROOT = Path(__file__).resolve().parents[1]
ID = re.compile(r'"((?:PKG|MODEL|DATA|TOOL|PROV|INTEGRITY|INTAKE|POLICY|LLM|CHECK|SCANNER|GPU)\.[A-Z0-9_.]*[A-Z0-9_])"')


def _emitted_ids() -> set[str]:
    ids: set[str] = set()
    for p in [*(ROOT / "lineage").rglob("*.py"), *(ROOT / "gpu_worker").rglob("*.py")]:
        if p.name in {"catalog.py"}:
            continue
        ids |= set(ID.findall(p.read_text()))
    return ids


def test_every_emitted_finding_id_has_a_catalogue_entry():
    missing = sorted(i for i in _emitted_ids() if checker_for(i) is None)
    assert not missing, f"explain these in lineage/catalog.py: {missing}"


def test_every_checker_points_at_a_real_function():
    for c in CHECKERS:
        module, _, fn = c.entry.partition(":")
        assert callable(getattr(importlib.import_module(module), fn)), c.entry


def test_names_are_plain():
    assert plain_name("CHECK.NOT_RUN.WEIGHT_BACKDOOR") == "Did not run: Weight-space backdoor score"
    assert plain_name("PROV.ORIGIN.UNVERIFIABLE") == "Does it match its claimed origin?"
    assert plain_name("MODEL.TEMPLATE.TRIGGER_BRANCH") == "Chat template backdoors"


def test_endpoint_serves_the_catalogue(tmp_path, policy_path):
    from fastapi.testclient import TestClient

    from lineage_server.app import create_app

    c = TestClient(create_app(tmp_path / "c.db", policy_path, require_auth=False))
    body = c.get("/catalog/checks").json()
    assert len(body["checkers"]) == len(CHECKERS) and "deterministic" in body["kinds"]
