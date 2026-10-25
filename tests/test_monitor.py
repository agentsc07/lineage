import json
from datetime import timedelta

import pytest

from lineage.policy.engine import decide
from lineage.schemas.artifact import ApprovalRequest
from lineage.schemas.policy import PolicyPack
from lineage_server import db, models, monitor, service
from tests.server_helpers import NOW, ago, finding, make_signed


@pytest.fixture
def policy(policy_path):
    return PolicyPack.from_yaml(policy_path)


@pytest.fixture
def conn(tmp_path):
    c = db.connect(tmp_path / "t.db")
    db.init_schema(c)
    return c


def admit(conn, policy, sp, env="dev"):
    d = decide(sp.passport.predicate, [], env, policy, NOW, artifact_id=sp.passport_id, released_at=ago(days=30))
    service.record(conn, sp, [], d, released_at=ago(days=30))
    return sp.passport_id


@pytest.fixture
def world(conn, policy):
    """pkg -> m1, m2 -> agent; plus an unrelated package."""
    pkg = make_signed("tokenizers-fast", "package", "0.9.2")
    other = make_signed("left-pad", "package", "1.0.0")
    m1 = make_signed("triage-llama", "model", parents=[pkg.passport_id])
    m2 = make_signed("triage-llama-q4", "model", parents=[pkg.passport_id])
    agent = make_signed("triage-agent", "agent", parents=[m1.passport_id, m2.passport_id])
    return {sp.passport.predicate.name: admit(conn, policy, sp) for sp in (pkg, other, m1, m2, agent)}


def advisory(sev="high", aid="GHSA-aaaa-bbbb-cccc"):
    def lookup(name, version):
        if name != "tokenizers-fast":
            return []
        return [finding(f"PKG.OSV.{aid}", sev, {"high": 25, "critical": 40, "medium": 12}[sev], detail="advisory")]
    return lookup


def test_new_advisory_raises_alert_with_blast_radius_and_updates_decisions(conn, policy, world):
    tick = monitor.tick(conn, policy=policy, lookup=advisory("high"), now=NOW)
    assert tick.checked == 2  # both admitted packages were re-queried
    (alert,) = tick.alerts
    assert alert.artifact_id == world["tokenizers-fast"] and alert.kind == "advisory" and alert.severity == "high"
    assert sorted(n.label.split("@")[0] for n in alert.blast_radius) == ["triage-agent", "triage-llama", "triage-llama-q4"]
    # package decision updated with the stored advisory; dev tolerates "high" so it stays admitted but riskier
    pkg = models.get_artifact(conn, world["tokenizers-fast"])
    assert any(f.id == "PKG.OSV.GHSA-aaaa-bbbb-cccc" for f in pkg.findings) and pkg.decision.risk_score == 25
    # dependents flagged and re-decided with a raised risk score
    for name in ("triage-llama", "triage-llama-q4", "triage-agent"):
        d = models.latest_decision(conn, world[name])
        assert d.risk_score >= 25 and any(f.id == "WATCH.PARENT.ADVISORY" for f in d.findings)
    assert models.latest_decision(conn, world["left-pad"]).risk_score == 0  # unrelated package untouched


def test_critical_advisory_in_prod_blocks_the_package(conn, policy, world):
    conn.execute("UPDATE decisions SET environment = 'prod'")
    conn.execute("UPDATE artifacts SET environment = 'prod'")
    tick = monitor.tick(conn, policy=policy, lookup=advisory("critical"), now=NOW)
    assert models.artifact_row(conn, world["tokenizers-fast"]).status == "blocked"
    assert "-> block" in tick.alerts[0].message


def test_tick_is_idempotent(conn, policy, world):
    monitor.tick(conn, policy=policy, lookup=advisory(), now=NOW)
    again = monitor.tick(conn, policy=policy, lookup=advisory(), now=NOW + timedelta(minutes=5))
    assert again.alerts == []


def test_a_second_distinct_advisory_alerts_again(conn, policy, world):
    monitor.tick(conn, policy=policy, lookup=advisory(aid="GHSA-1"), now=NOW)
    second = monitor.tick(conn, policy=policy, lookup=advisory(aid="GHSA-2"), now=NOW)
    assert len(second.alerts) == 1


def test_blocked_or_quarantined_packages_are_not_rechecked(conn, policy, world):
    service.revoke(conn, world["tokenizers-fast"], "x", policy, now=NOW)
    assert monitor.tick(conn, policy=policy, lookup=advisory(), now=NOW).checked == 1


def test_local_feed_file_is_an_advisory_source(conn, policy, world, tmp_path, monkeypatch):
    feed = tmp_path / "feed.json"
    feed.write_text(json.dumps({"tokenizers-fast==0.9.2": [{"id": "GHSA-feed-0001", "severity": "high", "summary": "RCE in decoder"}]}))
    monkeypatch.setenv("LINEAGE_ADVISORY_FEED", str(feed))
    tick = monitor.tick(conn, policy=policy, now=NOW)  # default lookup: package_osv stub -> skipped, feed -> used
    assert len(tick.alerts) == 1 and "RCE in decoder" in tick.alerts[0].message


def test_malicious_package_advisory_is_a_hard_block(conn, policy, world, tmp_path, monkeypatch):
    feed = tmp_path / "feed.json"
    feed.write_text(json.dumps({"tokenizers-fast==0.9.2": [{"id": "MAL-2026-1", "severity": "critical", "summary": "malware"}]}))
    monkeypatch.setenv("LINEAGE_ADVISORY_FEED", str(feed))
    monitor.tick(conn, policy=policy, now=NOW)
    assert models.artifact_row(conn, world["tokenizers-fast"]).status == "blocked"


def test_lookup_failure_does_not_abort_the_tick(conn, policy, world, monkeypatch):
    from lineage.inspect import package_osv

    def down(*a, **k):
        raise ConnectionError("osv unreachable")

    monkeypatch.setattr(package_osv, "scan", down)
    assert monitor.tick(conn, policy=policy, now=NOW).alerts == []


def test_lapsed_approval_raises_drift_alert_and_requarantines(conn, policy):
    tool = make_signed("tool", "tool")
    tid = admit(conn, policy, tool)  # quarantined: tools need a human
    service.approve(conn, tid, ApprovalRequest(approver="dr.rao", reason="ok", expires=NOW + timedelta(days=2)), policy, now=NOW)
    assert monitor.tick(conn, policy=policy, lookup=lambda n, v: [], now=NOW + timedelta(days=1)).alerts == []
    tick = monitor.tick(conn, policy=policy, lookup=lambda n, v: [], now=NOW + timedelta(days=3))
    assert [a.kind for a in tick.alerts] == ["drift"] and models.artifact_row(conn, tid).status == "quarantined"
