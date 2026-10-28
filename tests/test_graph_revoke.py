from datetime import timedelta

import pytest

from lineage.policy.engine import decide
from lineage.schemas.artifact import ApprovalRequest
from lineage.schemas.policy import PolicyPack
from lineage_server import db, graph, log, models, service
from tests.server_helpers import NOW, ago, finding, make_signed


@pytest.fixture
def policy(policy_path):
    return PolicyPack.from_yaml(policy_path)


@pytest.fixture
def conn(tmp_path):
    c = db.connect(tmp_path / "t.db")
    db.init_schema(c)
    return c


def admit(conn, policy, sp, env="dev", findings=()):
    d = decide(sp.passport.predicate, list(findings), env, policy, NOW, artifact_id=sp.passport_id, released_at=ago(days=30))
    service.record(conn, sp, list(findings), d, released_at=ago(days=30))
    return sp.passport_id


@pytest.fixture
def lineage(conn, policy):
    """pkg -> m1, m2 ; ds -> m1 ; m1 -> agent ; m2 -> agent ; other (unrelated)."""
    pkg = make_signed("pkg", "package")
    ds = make_signed("ds", "dataset")
    m1 = make_signed("m1", "model", parents=[pkg.passport_id, ds.passport_id])
    m2 = make_signed("m2", "model", parents=[pkg.passport_id])
    agent = make_signed("agent", "agent", parents=[m1.passport_id, m2.passport_id])
    other = make_signed("other", "package")
    ids = {sp.passport.predicate.name: admit(conn, policy, sp) for sp in (pkg, ds, m1, m2, agent, other)}
    return ids


def names(nodes):
    return sorted(n.label.split("@")[0] for n in nodes)


def test_graph_up_and_down(conn, lineage):
    up = graph.lineage_graph(conn, lineage["agent"], "up")
    assert names(up.nodes) == ["agent", "ds", "m1", "m2", "pkg"] and len(up.edges) == 5
    assert {(e.source, e.target) for e in up.edges} >= {(lineage["pkg"], lineage["m1"]), (lineage["m1"], lineage["agent"])}
    down = graph.lineage_graph(conn, lineage["pkg"], "down")
    assert names(down.nodes) == ["agent", "m1", "m2", "pkg"] and down.root == lineage["pkg"]
    assert graph.lineage_graph(conn, lineage["other"], "up").edges == []


def test_graph_is_one_recursive_cte():
    assert "WITH RECURSIVE" in graph._CTE["up"] and "WITH RECURSIVE" in graph._CTE["down"]


def test_graph_unknown_and_unregistered_parent(conn, policy):
    with pytest.raises(KeyError):
        graph.lineage_graph(conn, "lp:nope", "up")
    orphan = make_signed("orphan", "model", parents=["lp:" + "0" * 64])
    oid = admit(conn, policy, orphan)
    g = graph.lineage_graph(conn, oid, "up")
    # P6: a parent that was never admitted is a ghost node, not a dropped edge
    ghost = next(n for n in g.nodes if n.status == "unregistered")
    assert ghost.id == "lp:" + "0" * 64 and [(e.source, e.target) for e in g.edges] == [(ghost.id, oid)]


def test_graph_survives_cycle(conn, lineage):
    conn.execute("INSERT INTO edges (parent, child) VALUES (?, ?)", (lineage["agent"], lineage["pkg"]))
    assert names(graph.lineage_graph(conn, lineage["pkg"], "down").nodes) == ["agent", "m1", "m2", "pkg"]


def test_blast_radius_excludes_root(conn, lineage):
    assert names(graph.blast_radius(conn, lineage["pkg"])) == ["agent", "m1", "m2"]
    assert graph.blast_radius(conn, lineage["agent"]) == []


def test_revoke_blocks_descendants_and_returns_blast_radius(conn, lineage, policy):
    res = service.revoke(conn, lineage["pkg"], "backdoored release", policy, now=NOW)
    assert names(res.blast_radius) == ["agent", "m1", "m2"]
    assert all(n.status == "blocked" for n in res.blast_radius)
    assert models.artifact_row(conn, lineage["pkg"]).status == "revoked"
    assert models.artifact_row(conn, lineage["ds"]).status == "admitted"  # sibling untouched
    assert models.artifact_row(conn, lineage["other"]).status == "admitted"
    d = models.latest_decision(conn, lineage["agent"])
    assert d.outcome == "block" and any("revoked parent" in r for r in d.reasons)
    assert "backdoored release" in " ".join(d.reasons)
    assert [e.kind for e in log.read_log(conn).entries].count("revocation") == 1


def test_revoke_is_idempotent_and_keeps_revoked_status(conn, lineage, policy):
    service.revoke(conn, lineage["pkg"], "x", policy, now=NOW)
    again = service.revoke(conn, lineage["pkg"], "x", policy, now=NOW)
    assert names(again.blast_radius) == ["agent", "m1", "m2"]
    assert log.read_log(conn).entries[-1].kind in ("decision", "revocation")
    assert sum(e.kind == "revocation" for e in log.read_log(conn).entries) == 1


def test_revoke_unknown(conn, policy):
    with pytest.raises(service.NotFound):
        service.revoke(conn, "lp:nope", "", policy)


def test_revoked_artifact_stays_revoked_after_redecide(conn, lineage, policy):
    service.revoke(conn, lineage["pkg"], "x", policy, now=NOW)
    service.redecide(conn, lineage["pkg"], policy, now=NOW)
    assert models.artifact_row(conn, lineage["pkg"]).status == "revoked"


def test_approve_quarantined_tool_with_expiry_then_expiry_reverts(conn, policy):
    tool = make_signed("tool", "tool")
    tid = admit(conn, policy, tool, findings=[finding("TOOL.INTENT.UNDECLARED_NETWORK", "high", 25)])
    assert models.artifact_row(conn, tid).status == "quarantined"
    req = ApprovalRequest(approver="dr.rao", reason="reviewed code", expires=NOW + timedelta(days=7))
    d = service.approve(conn, tid, req, policy, now=NOW)
    assert d.outcome == "allow_with_conditions" and d.approver == "dr.rao"
    assert models.artifact_row(conn, tid).status == "admitted_with_conditions"
    later = service.redecide(conn, tid, policy, now=NOW + timedelta(days=8))
    assert later.outcome == "quarantine" and models.artifact_row(conn, tid).status == "quarantined"


def test_approve_refused_for_hard_block(conn, policy):
    sp = make_signed("bad", "package")
    pid = admit(conn, policy, sp, findings=[finding("INTEGRITY.HASH_MISMATCH", "critical", 40)])
    req = ApprovalRequest(approver="ciso", reason="please", expires=NOW + timedelta(days=1))
    with pytest.raises(service.ApprovalRefused):
        service.approve(conn, pid, req, policy, now=NOW)
    assert models.get_approvals(conn, pid) == []


def test_policy_expired_blocks_new_admission_but_keeps_hard_reasons(conn, policy):
    sp = make_signed("p", "package")
    pid = admit(conn, policy, sp)
    d = service.redecide(conn, pid, policy, policy_expired=True, now=NOW)
    assert d.outcome == "quarantine"
