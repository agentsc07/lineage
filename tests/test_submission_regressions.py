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
