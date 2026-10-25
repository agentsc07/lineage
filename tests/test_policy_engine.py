from datetime import date, timedelta

import pytest

from lineage.policy.engine import compliance_tags, decide
from lineage.risk import risk_score
from lineage.schemas.policy import PolicyException, PolicyPack
from tests.server_helpers import NOW, ago, finding, make_signed


@pytest.fixture
def policy(policy_path) -> PolicyPack:
    return PolicyPack.from_yaml(policy_path)


def body(**kw):
    return make_signed(**kw).passport.predicate


# --- risk ---
def test_risk_sums_caps_and_penalises_trust():
    fs = [finding(score=25, severity="high"), finding(score=12, severity="medium")]
    assert risk_score(fs, "inspected") == 37
    assert risk_score(fs, "declared") == 42
    assert risk_score(fs, "unknown") == 52
    assert risk_score([finding(score=40)] * 4, "unknown") == 100
    assert risk_score([], "inspected") == 0


def test_ungrounded_llm_finding_adds_nothing_and_nothing_subtracts():
    llm = finding("LLM.X", "high", 25, category="llm", source="llm", grounded=False)
    grounded = finding("LLM.Y", "high", 25, category="llm", source="llm", grounded=True)
    assert risk_score([llm], "inspected") == 0
    assert risk_score([grounded], "inspected") == 25
    base = [finding(score=10)]
    assert risk_score(base + [llm, grounded], "inspected") >= risk_score(base, "inspected")


# --- outcomes ---
def test_clean_artifact_is_allowed(policy):
    d = decide(body(name="ok", kind="dataset"), [], "prod", policy, NOW, released_at=ago(days=30))
    assert d.outcome == "allow" and d.policy_version == policy.version and d.risk_score == 0


def test_thresholds_per_environment(policy):
    mid = [finding(score=28, severity="high")]
    assert decide(body(name="p"), mid, "dev", policy, NOW).outcome == "allow"  # 28 <= 30
    d = decide(body(name="p"), mid, "prod", policy, NOW)  # prod allow limit is 25
    assert d.outcome == "quarantine" and any("allow limit" in r for r in d.reasons)
    assert decide(body(name="p"), [finding(score=40, severity="critical")] * 2, "dev", policy, NOW).outcome == "block"


def test_trust_below_environment_minimum_quarantines(policy):
    d = decide(body(name="p", trust_level="declared"), [], "prod", policy, NOW)
    assert d.outcome == "quarantine" and any("below prod minimum" in r for r in d.reasons)


def test_unknown_environment_rejected(policy):
    with pytest.raises(ValueError, match="unknown environment"):
        decide(body(name="p"), [], "qa", policy, NOW)


# --- hard blocks ---
@pytest.mark.parametrize(
    "fid, text",
    [
        ("PROV.SIGNATURE.INVALID", "signature failure"),
        ("INTEGRITY.HASH_MISMATCH", "hash mismatch"),
        ("PROV.PARENT.REVOKED", "revoked parent"),
        ("PKG.STARTUP.PTH_EXEC", "banned capability 'startup_hook'"),
        ("PKG.NETWORK_AT_INSTALL", "banned capability 'network_at_install'"),
        ("PKG.OSV.MAL.1", "known-malicious"),
        ("MODEL.PICKLE.DANGEROUS_GLOBAL", "pickle"),
    ],
)
def test_hard_blocks_ignore_score(policy, fid, text):
    d = decide(body(name="p"), [finding(fid, "high", 1)], "dev", policy, NOW)  # tiny score, still blocked
    assert d.outcome == "block" and any(text in r for r in d.reasons)


def test_pickle_model_file_blocks_unless_allowed(policy):
    b = body(name="m", kind="model", files={"weights.bin": "a" * 64})
    assert decide(b, [], "dev", policy, NOW).outcome == "block"
    ok = policy.model_copy(update={"model_files": policy.model_files.model_copy(update={"allow_pickle": True})})
    assert decide(b, [], "dev", ok, NOW).outcome == "allow"
    st = body(name="m", kind="model", files={"model.safetensors": "a" * 64})
    assert decide(st, [], "dev", policy, NOW).outcome == "allow"


def test_banned_capability_via_evidence_tag(policy):
    f = finding("PKG.CODE.X", "high", 25, detail="capability:network_at_install")
    assert decide(body(name="p"), [f], "dev", policy, NOW).outcome == "block"


def test_blocked_publisher(policy):
    d = decide(body(name="m", kind="model", repo="evil/llama-official-mirror"), [], "dev", policy, NOW)
    assert d.outcome == "block" and any("publisher blocked" in r for r in d.reasons)
    assert decide(body(name="m", kind="model", repo="meta-llama/x"), [], "dev", policy, NOW).outcome == "allow"


def test_hard_block_survives_exception(policy):
    exc = PolicyException(artifact="p", approver="ciso", reason="trust me", expires=date(2027, 1, 1))
    d = decide(body(name="p"), [finding("PROV.SIGNATURE.INVALID", "critical", 40)], "dev", policy, NOW, exceptions=[exc])
    assert d.outcome == "block" and d.approver is None


# --- cooldown ---
def test_cooldown_quarantines_young_release(policy):
    d = decide(body(name="p"), [], "dev", policy, NOW, released_at=ago(hours=2))
    assert d.outcome == "quarantine" and any(r.startswith("cooldown") for r in d.reasons)
    assert decide(body(name="p"), [], "dev", policy, NOW, released_at=ago(days=4)).outcome == "allow"  # package: 3 days


def test_cooldown_from_scanner_finding(policy):
    f = finding("PROV.COOLDOWN.PACKAGE", "medium", 12, category="provenance")
    assert decide(body(name="p"), [f], "dev", policy, NOW).outcome == "quarantine"


def test_cooldown_days_follow_artifact_type(policy):
    young = ago(days=5)
    assert decide(body(name="m", kind="model"), [], "dev", policy, NOW, released_at=young).outcome == "quarantine"
    assert decide(body(name="p"), [], "dev", policy, NOW, released_at=young).outcome == "allow"


# --- vulnerabilities, PII ---
def test_vuln_severity_limit_per_environment(policy):
    f = finding("PKG.OSV.GHSA-1", "high", 25, category="code")
    assert decide(body(name="p"), [f], "dev", policy, NOW).outcome == "allow"  # dev max: high
    assert decide(body(name="p"), [f], "prod", policy, NOW).outcome == "block"  # prod max: medium


def test_pii_blocked_unless_allowed(policy):
    f = finding("DATA.PII.EMAIL", "medium", 12, category="data")
    d = decide(body(name="d", kind="dataset"), [f], "dev", policy, NOW)
    assert d.outcome == "block" and any("compliance: ISO42001:A.7.5" in r for r in d.reasons)


# --- human approval + exceptions ---
def test_tool_needs_human_approval_then_exception_admits_with_conditions(policy):
    tool = body(name="t", kind="tool")
    q = decide(tool, [], "dev", policy, NOW, released_at=ago(days=30))
    assert q.outcome == "quarantine" and "human approval required by policy" in q.reasons
    exc = PolicyException(artifact="t", approver="dr.rao", reason="reviewed", expires=NOW + timedelta(days=7))
    d = decide(tool, [], "dev", policy, NOW, released_at=ago(days=30), exceptions=[exc])
    assert d.outcome == "allow_with_conditions" and d.approver == "dr.rao"
    assert any("dr.rao" in c for c in d.conditions) and "dev only" in d.conditions


def test_model_prod_requires_approval_but_not_dev(policy):
    m = body(name="m", kind="model")
    assert decide(m, [], "dev", policy, NOW).outcome == "allow"
    assert decide(m, [], "prod", policy, NOW).outcome == "quarantine"


def test_expired_exception_does_not_apply(policy):
    tool = body(name="t", kind="tool")
    exc = PolicyException(artifact="t", approver="dr.rao", reason="r", expires=NOW - timedelta(minutes=1))
    d = decide(tool, [], "dev", policy, NOW, exceptions=[exc])
    assert d.outcome == "quarantine" and any("expired" in r for r in d.reasons)


def test_exception_in_policy_file_matches_name_version_and_date_expiry(policy):
    pol = policy.model_copy(update={"exceptions": [
        PolicyException(artifact="p@1.0.0", approver="ciso", reason="legacy", expires=date(2026, 10, 26)),  # end of day
    ]})
    risky = [finding(score=40, severity="critical"), finding(score=35, severity="high")]
    assert decide(body(name="p"), risky, "dev", pol, NOW).outcome == "allow_with_conditions"
    later = NOW + timedelta(days=1)
    assert decide(body(name="p"), risky, "dev", pol, later).outcome == "block"


def test_policy_expired_fails_closed_for_clean_artifact(policy):
    d = decide(body(name="p"), [], "dev", policy, NOW, policy_expired=True)
    assert d.outcome == "quarantine" and any("expired" in r for r in d.reasons)


def test_compliance_tags_follow_categories(policy):
    fs = [finding("A", "medium", 12, category="provenance"), finding("B", "info", 0, category="data")]
    assert compliance_tags(fs, policy) == ["NIST-AI-RMF:MAP-4.1 <- provenance"]
    d = decide(body(name="p"), fs, "dev", policy, NOW)
    assert "compliance: NIST-AI-RMF:MAP-4.1 <- provenance" in d.reasons


def test_decision_is_deterministic(policy):
    a = decide(body(name="p"), [finding(score=10)], "dev", policy, NOW)
    b = decide(body(name="p"), [finding(score=10)], "dev", policy, NOW)
    assert a == b
