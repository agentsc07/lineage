"""One test against the real Hugging Face hub, off by default: LINEAGE_TEST_REAL_HUB=1 uv run pytest tests/test_real_hub.py
It fetches a ~6 MB public test model by commit sha (needs internet, no token) and runs it through intake as `hf:<repo>@<sha>`."""
import os

import httpx
import pytest

from lineage.intake.pipeline import run_to_decision
from lineage.schemas.policy import PolicyPack
from tests.server_helpers import NOW

REPO = "hf-internal-testing/tiny-random-LlamaForCausalLM"
pytestmark = pytest.mark.skipif(os.environ.get("LINEAGE_TEST_REAL_HUB") != "1", reason="set LINEAGE_TEST_REAL_HUB=1 to hit huggingface.co")


def test_a_real_public_model_is_fetched_verified_and_decided(tmp_path, policy_path):
    sha = httpx.get(f"https://huggingface.co/api/models/{REPO}", timeout=30).json()["sha"]
    d, events = run_to_decision("model", "", "dev", PolicyPack.from_yaml(policy_path), "real", now=NOW, source=f"hf:{REPO}@{sha}", work_dir=tmp_path / "w")
    ids = {f.id for f in d.findings}
    s0 = next(e for e in events if e.stage == "S0" and e.status != "started")
    assert s0.status == "completed" and "fetched" in s0.message
    assert d.trust_level == "origin_verified" and "PROV.ORIGIN.VERIFIED" in ids and "CHECK.NOT_RUN.ACQUIRE" not in ids
    assert any((tmp_path / "w").rglob("model.safetensors")) and not any((tmp_path / "w").rglob("*.onnx"))  # allow-patterns: no ONNX
    print(d.outcome, d.risk_score, sorted(ids))
