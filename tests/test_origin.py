"""R2.1-R2.4 / test 2: fetch from a (fake) hub, keep the bytes, and compare an upload with what its claimed origin published."""
import shutil
import zipfile

import pytest
from fastapi.testclient import TestClient

from lineage.intake.hub import HttpHub
from lineage.intake.pipeline import run_to_decision
from lineage.schemas.policy import PolicyPack
from lineage.store import Store
from tests.fakehub import create_app
from tests.fixtures.builders import make_tiny_model
from tests.server_helpers import NOW

REPO = "acme/tiny"


@pytest.fixture
def policy(policy_path):
    return PolicyPack.from_yaml(policy_path)


@pytest.fixture
def hubroot(tmp_path):
    root = tmp_path / "hub"
    make_tiny_model(root / "models" / "acme" / "tiny")
    (root / "models" / "acme" / "tiny" / "README.md").write_text("---\nlicense: mit\n---\n# tiny\n")
    wheel = root / "pypi" / "toypkg" / "1.0.0" / "toypkg-1.0.0-py3-none-any.whl"
    wheel.parent.mkdir(parents=True)
    with zipfile.ZipFile(wheel, "w") as z:
        z.writestr("toypkg/__init__.py", "def f():\n    return 1\n")
        z.writestr("toypkg-1.0.0.dist-info/METADATA", "Name: toypkg\nVersion: 1.0.0\n")
    return root


@pytest.fixture
def hub(hubroot):
    records = {f"hf:{REPO}": {"released_at": "2025-01-01T00:00:00Z", "licence": "mit"},
               "pypi:toypkg==1.0.0": {"released_at": "2025-01-01T00:00:00Z", "description": "toy"}}
    return HttpHub(base_url="http://testserver", client=TestClient(create_app(hubroot, records)), trusted_local=False)


def run(kind, ref, policy, hub, env="prod", **kw):
    kw.setdefault("now", NOW)
    return run_to_decision(kind, str(ref), env, policy, "j", hub=hub, **kw)


def ids(d):
    return {f.id for f in d.findings}


def test_fetched_model_is_origin_verified_with_fetched_facts_and_kept_in_the_store(policy, hub, tmp_path):
    store = Store(tmp_path / "store")
    d, events = run("model", "", policy, hub, source=f"hf:{REPO}", store=store, work_dir=tmp_path / "w")
    assert d.trust_level == "origin_verified" and "PROV.ORIGIN.VERIFIED" in ids(d)
    assert "PROV.COOLDOWN.UNVERIFIED" not in ids(d)  # the release date is fetched
    s0 = next(e for e in events if e.stage == "S0" and e.status != "started")
    assert s0.status == "completed" and "fetched" in s0.message
    # every inspected file is in the store (P4)
    import hashlib
    for p in (tmp_path / "w").rglob("*.safetensors"):
        assert store.has(hashlib.sha256(p.read_bytes()).hexdigest())


def test_unreachable_hub_cannot_acquire_and_blocks(policy, tmp_path):
    dead = HttpHub(base_url="http://127.0.0.1:9", trusted_local=False)
    d, _ = run("model", "", policy, dead, source=f"hf:{REPO}", work_dir=tmp_path / "w")
    assert "CHECK.NOT_RUN.ACQUIRE" in ids(d) and d.outcome == "block"
    assert not any(f.id == "INTAKE.DIGEST.KNOWN" for f in d.findings) and d.risk_score <= 100
    from lineage.intake.pipeline import run_intake

    s1 = next(e for e in run_intake("model", "", "dev", PolicyPack.from_yaml("examples/policy.org.yaml"), "j", hub=dead, source=f"hf:{REPO}", work_dir=tmp_path / "w2", now=NOW)
              if e.stage == "S1" and e.status != "started")
    assert "0 file(s)" not in s1.message and "hashed" not in s1.message  # nothing was hashed: an empty ref is not the current directory


def test_upload_matching_the_published_repo_is_origin_verified(policy, hub, hubroot, tmp_path):
    upload = tmp_path / "up"
    shutil.copytree(hubroot / "models" / "acme" / "tiny", upload)
    d, _ = run("model", upload, policy, hub, claimed_origin=f"hf:{REPO}")
    assert d.trust_level == "origin_verified" and "PROV.ORIGIN.VERIFIED" in ids(d)
    assert "PROV.COOLDOWN.UNVERIFIED" not in ids(d)  # facts about the repo became fetched because the hashes matched


def test_one_changed_byte_is_modified_and_a_hard_block_in_prod(policy, hub, hubroot, tmp_path):
    upload = tmp_path / "up"
    shutil.copytree(hubroot / "models" / "acme" / "tiny", upload)
    w = upload / "model.safetensors"
    b = bytearray(w.read_bytes())
    b[-1] ^= 0xFF
    w.write_bytes(bytes(b))
    d, _ = run("model", upload, policy, hub, claimed_origin=f"hf:{REPO}")
    f = next(f for f in d.findings if f.id == "PROV.ORIGIN.MODIFIED")
    assert f.severity == "critical" and any("model.safetensors" in e.ref for e in f.evidence)
    assert d.outcome == "block" and any("modified copy" in r for r in d.reasons) and d.trust_level == "unknown"
    # in dev it is critical but not a hard block by itself
    dev, _ = run("model", upload, policy, hub, env="dev", claimed_origin=f"hf:{REPO}")
    assert not any("modified copy" in r for r in dev.reasons)


def test_extra_and_missing_files_are_modifications(policy, hub, hubroot, tmp_path):
    upload = tmp_path / "up"
    shutil.copytree(hubroot / "models" / "acme" / "tiny", upload)
    (upload / "extra.py").write_text("print(1)\n")
    (upload / "README.md").unlink()
    d, _ = run("model", upload, policy, hub, claimed_origin=f"hf:{REPO}")
    f = next(f for f in d.findings if f.id == "PROV.ORIGIN.MODIFIED")
    detail = " ".join(e.detail for e in f.evidence)
    assert "extra.py" in detail and "README.md" in detail


def test_no_claim_is_unknown_and_unclaimed_and_hints_are_not_trusted(policy, hubroot, tmp_path):
    upload = tmp_path / "up"
    shutil.copytree(hubroot / "models" / "acme" / "tiny", upload)
    (upload / "config.json").write_text('{"_name_or_path": "meta-llama/Llama-3.2-1B"}')
    hub = HttpHub(base_url="http://testserver", client=TestClient(create_app(hubroot)), trusted_local=False)
    d, _ = run("model", upload, policy, hub)
    assert d.trust_level == "unknown" and "PROV.ORIGIN.UNCLAIMED" in ids(d)
    hint = next(f for f in d.findings if f.id == "PROV.ORIGIN.HINT")
    assert "meta-llama/Llama-3.2-1B" in hint.title and "not used for trust" in hint.title


def test_claim_that_cannot_be_checked_is_unverifiable(policy, hub, hubroot, tmp_path):
    upload = tmp_path / "up"
    shutil.copytree(hubroot / "models" / "acme" / "tiny", upload)
    d, _ = run("model", upload, policy, hub, claimed_origin="hf:nobody/nothing")
    assert "PROV.ORIGIN.UNVERIFIABLE" in ids(d) and d.trust_level == "unknown"


def test_pypi_fetch_verifies_the_wheel_hash_and_keeps_the_wheel(policy, hub, tmp_path):
    store = Store(tmp_path / "store")
    d, _ = run("package", "", policy, hub, source="pypi:toypkg==1.0.0", store=store, work_dir=tmp_path / "w")
    assert d.trust_level == "origin_verified" and "INTEGRITY.FETCH_MISMATCH" not in ids(d)
    assert d.artifact_id


def test_pypi_hash_mismatch_is_a_hard_block(policy, hubroot, tmp_path):
    app = create_app(hubroot)
    client = TestClient(app)
    orig = client.get

    def tampered(url, *a, **k):
        r = orig(url, *a, **k)
        if "/files/" in str(url):
            r._content = r.content + b"x"
        return r

    client.get = tampered  # type: ignore[method-assign]
    hub = HttpHub(base_url="http://testserver", client=client, trusted_local=False)
    d, _ = run("package", "", policy, hub, source="pypi:toypkg==1.0.0", work_dir=tmp_path / "w")
    assert "INTEGRITY.FETCH_MISMATCH" in ids(d) and d.outcome == "block"


def test_safe_extract_refuses_path_traversal(tmp_path):
    from lineage.intake.fetch import AcquireError, safe_extract

    z = tmp_path / "evil.zip"
    with zipfile.ZipFile(z, "w") as f:
        f.writestr("../escape.txt", "x")
    with pytest.raises(AcquireError):
        safe_extract(z, tmp_path / "out")
    assert not (tmp_path / "escape.txt").exists()
