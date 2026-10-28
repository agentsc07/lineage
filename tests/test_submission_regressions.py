"""Regression tests for the submission review: PII on loopback addresses, and a crashed check never counting as a pass."""
from lineage.inspect import dataset_pii
from lineage.intake import inspectors as insp
from lineage.policy.engine import decide
from lineage.schemas.policy import PolicyPack
from tests.server_helpers import NOW, ago, finding, make_signed
import pytest


@pytest.fixture
def policy(policy_path) -> PolicyPack:
    return PolicyPack.from_yaml(policy_path)


def body(**kw):
    return make_signed(**kw).passport.predicate


def test_loopback_private_and_documentation_addresses_are_not_personal_data(tmp_path):
    f = tmp_path / "d.jsonl"
    f.write_text("\n".join(['{"t": "open http://127.0.0.1:9/setup"}', '{"t": "host 10.0.0.5 and 192.168.1.2 and 192.0.2.7"}']))
    assert dataset_pii.scan(f) == []


def test_a_public_address_is_still_reported_but_only_as_low(tmp_path):
    f = tmp_path / "d.jsonl"
    f.write_text('{"t": "client 8.8.8.8 called"}\n')
    out = dataset_pii.scan(f)
    assert [x.id for x in out] == ["DATA.PII.IP_ADDRESS"] and out[0].severity == "low"


def test_an_ip_address_alone_does_not_block_but_an_email_still_does(policy):
    ip = finding("DATA.PII.IP_ADDRESS", "low", 5, category="data")
    mail = finding("DATA.PII.EMAIL", "medium", 12, category="data")
    assert not policy.data.pii_allowed
    assert decide(body(name="d", kind="dataset"), [ip], "dev", policy, NOW, released_at=ago(days=30)).outcome == "allow"
    assert decide(body(name="d", kind="dataset"), [mail], "dev", policy, NOW, released_at=ago(days=30)).outcome == "block"


def test_a_scanner_that_crashes_is_reported_and_is_never_a_pass():
    def boom(ctx):
        raise RuntimeError("scanner exploded")

    got = insp.run_inspector("boom", boom, object(), "S3")
    assert [f.id for f in got] == ["SCANNER.ERROR.BOOM"] and got[0].severity == "medium"


@pytest.mark.parametrize("env", ["dev", "staging", "prod"])
@pytest.mark.parametrize("fid", ["SCANNER.ERROR.PII", "INTAKE.STAGE.ERROR"])
def test_a_failed_check_forces_a_human_decision_in_every_environment(policy, env, fid):
    f = finding(fid, "medium", 12, category="policy")
    d = decide(body(name="d", kind="dataset", trust_level="signed"), [f], env, policy, NOW, released_at=ago(days=30))
    assert d.outcome in ("quarantine", "block") and any("failed to complete" in r for r in d.reasons)


def test_a_check_that_did_not_run_is_priced_by_environment_and_acquire_is_a_hard_block(policy):
    nr = finding("CHECK.NOT_RUN.LLM_REVIEW", "info", 0, category="policy")
    dev = decide(body(name="d", kind="dataset", trust_level="signed"), [nr], "dev", policy, NOW, released_at=ago(days=30))
    prod = decide(body(name="d", kind="dataset", trust_level="signed"), [nr], "prod", policy, NOW, released_at=ago(days=30))
    assert dev.risk_score == 0 and prod.risk_score == 25  # the policy prices it: free in dev, high in prod
    acq = finding("CHECK.NOT_RUN.ACQUIRE", "critical", 40, category="integrity")
    assert decide(body(name="d", kind="dataset"), [acq], "dev", policy, NOW, released_at=ago(days=30)).outcome == "block"


def test_a_claim_that_abbreviates_a_long_literal_with_an_ellipsis_is_still_grounded():
    """The real line of the demo's compromised wheel; the model wrote '...' for the payload and the claim used to be dropped."""
    from lineage.inspect.llm_review.grounding import api_on_line

    line = "import base64; exec(base64.b64decode('aW1wb3J0IG9zOyBvcy5zeXN0ZW0oJ3RvdWNoIC90bXAvbGluZWFnZV9tYXJrZXJfeCcp'))"
    assert api_on_line("import base64; exec(base64.b64decode(...))", line)
    assert api_on_line("exec(base64.b64decode(...))", line)
    assert not api_on_line("subprocess.run(...)", line)            # fragments that are not on the line stay ungrounded
    assert not api_on_line("os.system(...)", line)
    assert not api_on_line("...", line) and not api_on_line("(...)", line)  # an ellipsis alone proves nothing


# --- gpu_weights must not contradict the local parent check (Brev run: worker bank empty, local bank has the parent) ---
class _BankRegistry:
    """Only what gpu_weights asks of a registry: the admitted models on this host."""

    def __init__(self, bank):
        self.bank = bank

    def reference_models(self):
        return self.bank


def _weights_ctx(tmp_path, policy_path, local_findings, bank):
    from lineage.intake.inspectors import IntakeContext
    from lineage.schemas.finding import Evidence

    pol = PolicyPack.from_yaml(policy_path)
    model = tmp_path / "child"; model.mkdir(); (model / "model.safetensors").write_bytes(b"x")
    ctx = IntakeContext(artifact_type="model", ref=str(model), environment="prod", policy=pol, registry=_BankRegistry(bank), now=NOW, path=model)
    ctx.findings = [insp.make_finding(fid, "t", "info", "model", "S4", [Evidence(kind="field", ref="lp:parent", detail="triage-base@1")]) for fid in local_findings]
    return ctx


def _fake_worker(monkeypatch, calls):
    from lineage.intake import gpu
    from lineage.schemas.gpu import BehaviourDiffResponse, ParentResponse, SpectralResponse

    def post(path, request, response_model, base_url=None, timeout=0):
        calls.append((path, getattr(request, "parent", None)))
        if path == "/weights/parent":
            return ParentResponse(parent=None, similarity=0.0, changed_layers=[])  # the worker's own bank is empty
        if path == "/weights/spectral":
            return SpectralResponse(score=0.1, per_layer={})
        if path == "/behaviour/diff":
            return BehaviourDiffResponse(divergence=0.0, flagged_probes=[])
        raise AssertionError(path)

    monkeypatch.setattr(gpu, "post", post)


def test_identical_to_an_admitted_parent_is_not_reported_as_unidentified_or_not_run(tmp_path, policy_path, monkeypatch):
    calls: list = []
    _fake_worker(monkeypatch, calls)
    parent_dir = tmp_path / "parent"; parent_dir.mkdir()
    ctx = _weights_ctx(tmp_path, policy_path, ["MODEL.PARENT.IDENTICAL"], {"lp:parent": ("triage-base@1", parent_dir)})
    got = {f.id for f in insp.gpu_weights(ctx)}
    assert got == {"MODEL.WEIGHTS.NO_DELTA"}  # no UNIDENTIFIED (+5), no CHECK.NOT_RUN.* (+24)


def test_a_parent_found_locally_but_unknown_to_the_worker_is_compared_not_silently_skipped(tmp_path, policy_path, monkeypatch):
    calls: list = []
    _fake_worker(monkeypatch, calls)
    parent_dir = tmp_path / "parent"; parent_dir.mkdir()
    ctx = _weights_ctx(tmp_path, policy_path, ["MODEL.PARENT.IDENTIFIED"], {"lp:parent": ("triage-base@1", parent_dir)})
    got = {f.id for f in insp.gpu_weights(ctx)}
    assert ("/weights/spectral", str(parent_dir)) in calls and ("/behaviour/diff", str(parent_dir)) in calls  # the worker is told which directory
    assert not any(i.startswith("CHECK.NOT_RUN") or i == "MODEL.PARENT.UNIDENTIFIED" for i in got)


def test_no_parent_anywhere_is_unidentified_and_both_checks_are_priced_as_not_run(tmp_path, policy_path, monkeypatch):
    calls: list = []
    _fake_worker(monkeypatch, calls)
    ctx = _weights_ctx(tmp_path, policy_path, [], {})
    got = {f.id for f in insp.gpu_weights(ctx)}
    assert got == {"MODEL.PARENT.UNIDENTIFIED", "CHECK.NOT_RUN.WEIGHT_BACKDOOR", "CHECK.NOT_RUN.BEHAVIOUR_DIFF"}


def test_a_refused_api_call_does_not_make_a_browser_open_its_own_login_dialog(tmp_path, policy_path):
    """Basic auth challenges pop up a native login box in a browser; only the pip index (which pip answers with Basic credentials) may use one."""
    from fastapi.testclient import TestClient
    from lineage_server.app import create_app

    api = TestClient(create_app(tmp_path / "p.db", policy_path, require_auth=True))
    r = api.get("/artifacts")
    assert r.status_code == 401 and r.headers["www-authenticate"].startswith("Bearer")
    assert api.get("/whoami").headers["www-authenticate"].startswith("Bearer")
    assert api.get("/simple/").headers["www-authenticate"].startswith("Basic")


def test_a_broken_local_policy_model_does_not_fail_the_card_review(monkeypatch):
    """Brev: /review/card answered 500 because the optional local policy model (not downloaded) raised. It must be skipped instead."""
    import sys
    import types

    from gpu_worker import reviewer_api

    def boom(*a, **k):
        raise OSError("nvidia/Nemotron-Content-Safety-Reasoning-4B is not in the local cache")

    monkeypatch.setitem(sys.modules, "gpu_worker.modelio", types.SimpleNamespace(have_gpu=lambda: True))
    monkeypatch.setitem(sys.modules, "gpu_worker.policy_check", types.SimpleNamespace(check=boom))
    import gpu_worker
    monkeypatch.setattr(gpu_worker, "modelio", sys.modules["gpu_worker.modelio"], raising=False)
    monkeypatch.setattr(gpu_worker, "policy_check", sys.modules["gpu_worker.policy_check"], raising=False)
    assert reviewer_api._policy_claims("card", "# card\nlicense: mit\n", "card.md") == []


def test_no_delta_is_named_after_the_gpu_check_not_the_parent_search():
    from lineage.catalog import checker_for

    assert checker_for("MODEL.WEIGHTS.NO_DELTA").key == "spectral"
    assert checker_for("MODEL.PARENT.IDENTICAL").key == "parent_id" and checker_for("MODEL.PARENT.NO_CLAIMED_BASE").key == "hub_parent"
