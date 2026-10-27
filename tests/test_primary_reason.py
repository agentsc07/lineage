"""F2: the decision headline is the rule that set the outcome; everything else that applied is `secondary_reasons`."""
from datetime import timedelta

import pytest

from lineage.policy.engine import decide
from lineage.schemas.policy import PolicyException, PolicyPack
from tests.server_helpers import NOW, ago, finding, make_signed


@pytest.fixture
def policy(policy_path) -> PolicyPack:
    return PolicyPack.from_yaml(policy_path)


def body(**kw):
    return make_signed(**kw).passport.predicate


def criticals(n=3):
    return [finding(f"MODEL.TEMPLATE.X{i}", "critical", 40) for i in range(n)]


def test_step_4_backdoored_template_headline_is_the_risk_and_its_findings_not_the_cooldown(policy):
    d = decide(body(name="m", kind="model"), criticals(), "dev", policy, NOW, released_at=ago(hours=1))  # a young release as well
    assert d.outcome == "block" and d.risk_score == 100
    assert d.primary_reason.startswith("risk 100 > 70") and "critical MODEL.TEMPLATE.X0" in d.primary_reason
    assert any(r.startswith("cooldown") for r in d.secondary_reasons) and d.reasons[0] == d.primary_reason


def test_step_6_poisoned_dataset_headline_is_the_risk(policy):
    fs = [finding("DATA.TRIGGER.BEHAVIOUR", "high", 25), finding("DATA.INJECT.URL", "high", 25), finding("DATA.CHARS.ZERO", "medium", 12)]
    d = decide(body(name="d", kind="dataset", trust_level="unknown"), fs * 1 + [finding("DATA.X", "high", 25)], "prod", policy, NOW)
    assert d.outcome == "block" and d.primary_reason.startswith("risk ") and "(block threshold)" in d.primary_reason


def test_step_2_prod_model_over_the_allow_limit_is_headed_by_the_human_approval(policy):
    d = decide(body(name="m", kind="model", trust_level="origin_verified"), [finding("X.A", "high", 25), finding("X.B", "high", 25)],
               "prod", policy, NOW, released_at=ago(days=30))
    assert d.outcome == "quarantine" and d.risk_score == 55
    assert d.primary_reason == "human approval required by policy"
    assert any(r.startswith("risk 55 > 25") for r in d.secondary_reasons)


def test_cooldown_and_a_critical_finding_both_apply_the_finding_leads(policy):
    d = decide(body(name="p"), [finding("PKG.TAINT.ENV_EXFIL", "critical", 40)], "dev", policy, NOW, released_at=ago(hours=1))
    assert d.outcome == "quarantine"
    assert "critical PKG.TAINT.ENV_EXFIL" in d.primary_reason and not d.primary_reason.startswith("cooldown")
    assert any(r.startswith("cooldown") for r in d.secondary_reasons)


def test_cooldown_alone_is_the_primary_reason(policy):
    d = decide(body(name="p"), [], "dev", policy, NOW, released_at=ago(hours=1))
    assert d.outcome == "quarantine" and d.primary_reason.startswith("cooldown") and d.secondary_reasons == []


def test_a_hard_block_floor_beats_a_soft_block(policy):
    fs = [finding("PROV.SIGNATURE.INVALID", "critical", 40), *criticals(2)]
    d = decide(body(name="p"), fs, "dev", policy, NOW)
    assert d.outcome == "block" and d.primary_reason.startswith("signature failure")
    assert any(r.startswith("risk ") for r in d.secondary_reasons)


def test_an_approved_exception_is_the_primary_reason_and_names_its_approver(policy):
    tool = body(name="t", kind="tool")
    exc = PolicyException(artifact="t", approver="dr.rao", reason="reviewed", expires=NOW + timedelta(days=7))
    d = decide(tool, [], "dev", policy, NOW, released_at=ago(days=30), exceptions=[exc])
    assert d.outcome == "allow_with_conditions" and d.primary_reason.startswith("approved by dr.rao")
    assert any("human approval required by policy" in r for r in d.secondary_reasons)


def test_allow_has_a_primary_reason_and_no_secondary(policy):
    d = decide(body(name="ok", kind="dataset"), [], "prod", policy, NOW, released_at=ago(days=30))
    assert d.outcome == "allow" and d.primary_reason and d.secondary_reasons == []
