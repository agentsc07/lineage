"""R3.4, R3.5 / tests 7 and 9: ghost nodes, edges for every reference, and the scheduled monitor (REFACTOR_SPEC 6)."""
import shutil
import time

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from lineage.intake.hub import HttpHub
from lineage.intake.pipeline import run_to_decision
from lineage.schemas.finding import Evidence, Finding
from lineage.schemas.passport import Action, SbomComponent
from lineage.schemas.policy import PolicyPack, TrustedPublisher
from lineage_server import db, graph, models, monitor, service, trust
from lineage_server.registry import SqliteRegistry
from tests.fakehub import create_app as create_hub, old_release_hub
from tests.fixtures.builders import make_tiny_model
from tests.server_helpers import NOW
from tests.test_signature_scope import passport_for


@pytest.fixture
def conn(tmp_path):
    c = db.connect(tmp_path / "g.db")
    db.init_schema(c)
    return c


@pytest.fixture
def apollo():
    return Ed25519PrivateKey.generate()


@pytest.fixture
def policy(policy_path, apollo):
    p = PolicyPack.from_yaml(policy_path)
    return p.model_copy(update={"trusted_publishers": [TrustedPublisher(name="Apollo", key=trust.public_hex(apollo.public_key()), scope=["upload:*"])],
                                "unrun_checks": {"default": {"dev": "info", "staging": "info", "prod": "info"}}})


@pytest.fixture
def registry(conn):
    return SqliteRegistry(conn, Ed25519PrivateKey.generate())


def advisory(name, version):
    if (name, version) != ("torch", "2.4.1"):
        return []
    return [Finding(id="PKG.OSV.GHSA-torch-0001", title="GHSA-torch-0001: pickle RCE", severity="high", category="code", stage="S3",
                    evidence=[Evidence(kind="field", ref="GHSA-torch-0001")], score=25, source="deterministic")]


@pytest.fixture
def trained(conn, registry, policy, apollo, tmp_path):
    """A model trained by `lineage run`: signed passport with an SBOM naming torch, which nobody admitted."""
    m = make_tiny_model(tmp_path / "trained")
    passport_for(m, apollo, None, hub="local-run", action=Action(kind="train"), inputs={"data.csv": "a" * 64},
                 sbom=[SbomComponent(name="torch", version="2.4.1", purl="pkg:pypi/torch@2.4.1")])
    d, _ = run_to_decision("model", str(m), "dev", policy, "j", now=NOW, hub=old_release_hub(), registry=registry)
    assert d.trust_level == "recorded"
    return d.artifact_id


def test_sbom_components_are_ghost_nodes_with_built_with_edges(conn, trained):
    g = graph.lineage_graph(conn, trained, "up")
    ghost = next(n for n in g.nodes if n.status == "unregistered")
    assert ghost.id == "ghost:package:torch@2.4.1" and ghost.trust_level == "unknown"
    assert [(e.source, e.target, e.kind) for e in g.edges] == [(ghost.id, trained, "built_with")]


def test_an_advisory_on_a_ghost_package_flags_the_model_trained_with_it(conn, trained, policy):
    result = monitor.tick(conn, policy=policy, lookup=advisory, now=NOW)
    alert = next(a for a in result.alerts if a.artifact_id == "ghost:package:torch@2.4.1")
    assert alert.kind == "advisory" and [n.id for n in alert.blast_radius] == [trained]
    flagged = models.get_findings(conn, trained)
    assert any(f.id == "WATCH.PARENT.ADVISORY" for f in flagged)
    assert monitor.tick(conn, policy=policy, lookup=advisory, now=NOW).alerts == []  # idempotent


def test_a_registered_package_replaces_the_ghost_edge(conn, registry, policy, apollo, tmp_path):
    from tests.server_helpers import ago, make_signed
    from lineage.policy.engine import decide

    pkg = make_signed("torch", "package", "2.4.1")
    service.record(conn, pkg, [], decide(pkg.passport.predicate, [], "dev", policy, NOW, artifact_id=pkg.passport_id, released_at=ago(days=30)), released_at=ago(days=30))
    m = make_tiny_model(tmp_path / "m2")
    passport_for(m, apollo, None, hub="local-run", action=Action(kind="train"), sbom=[SbomComponent(name="torch", version="2.4.1", purl="pkg:pypi/torch@2.4.1")])
    d, _ = run_to_decision("model", str(m), "dev", policy, "j", now=NOW, hub=old_release_hub(), registry=registry)
    g = graph.lineage_graph(conn, d.artifact_id, "up")
    assert [n.id for n in g.nodes if n.status == "unregistered"] == [] and pkg.passport_id in [e.source for e in g.edges]


def test_a_ghost_can_be_revoked_and_the_blast_radius_follows(conn, trained, policy):
    r = service.revoke(conn, "ghost:package:torch@2.4.1", "compromised release", policy)
    assert [n.id for n in r.blast_radius] == [trained]
    assert models.artifact_row(conn, trained).status == "blocked"


def _wheel(path, name, version):
    import zipfile

    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w") as z:
        z.writestr(f"{name}/__init__.py", "def f():\n    return 1\n")
        z.writestr(f"{name}-{version}.dist-info/METADATA", f"Name: {name}\nVersion: {version}\n")


def test_unregistered_dependencies_become_ghosts_with_a_finding(tmp_path, policy, registry, conn):
    root = tmp_path / "hub"
    _wheel(root / "pypi" / "app" / "1.0.0" / "app-1.0.0-py3-none-any.whl", "app", "1.0.0")
    records = {"pypi:app==1.0.0": {"released_at": "2025-01-01T00:00:00Z", "requires_dist": ["requests>=2", "tqdm; extra == 'progress'"]}}
    hub = HttpHub(base_url="http://testserver", client=TestClient(create_hub(root, records)), trusted_local=False)
    d, _ = run_to_decision("package", "", "dev", policy, "j", now=NOW, hub=hub, registry=registry, source="pypi:app==1.0.0", work_dir=tmp_path / "w")
    assert [f.title for f in d.findings if f.id == "PKG.DEP.UNREGISTERED"] == ["Dependency requests has not been admitted"]  # the extra-only dep is skipped
    g = graph.lineage_graph(conn, d.artifact_id, "up")
    assert [(n.id, n.status) for n in g.nodes if n.status == "unregistered"] == [("ghost:package:requests@*", "unregistered")]
    assert [e.kind for e in g.edges] == ["depends_on"]


# --- monitor (test 9) ---
@pytest.fixture
def hub_world(tmp_path, policy, registry, conn):
    root = tmp_path / "hub"
    repo = make_tiny_model(root / "models" / "acme" / "tiny")
    hub = HttpHub(base_url="http://testserver", client=TestClient(create_hub(root, {"hf:acme/tiny": {"released_at": "2025-01-01T00:00:00Z"}})), trusted_local=False)
    d, _ = run_to_decision("model", "", "dev", policy, "j", now=NOW, hub=hub, registry=registry, source="hf:acme/tiny", work_dir=tmp_path / "w")
    assert d.outcome == "allow", d.reasons
    return d.artifact_id, root, hub, repo


def test_hub_drift_changed_is_an_info_alert_and_removed_re_decides(hub_world, conn, policy):
    aid, root, hub, repo = hub_world
    assert monitor.tick(conn, policy=policy, lookup=lambda n, v: [], now=NOW, hub=hub).alerts == []
    (repo / "README.md").write_text("# a new commit upstream\n")
    r = monitor.tick(conn, policy=policy, lookup=lambda n, v: [], now=NOW, hub=hub)
    a = next(x for x in r.alerts if x.artifact_id == aid)
    assert a.severity == "info" and "changed upstream" in a.message and models.artifact_row(conn, aid).status == "admitted"  # bytes are pinned
    assert monitor.tick(conn, policy=policy, lookup=lambda n, v: [], now=NOW, hub=hub).alerts == []  # not repeated
    shutil.rmtree(repo)
    r = monitor.tick(conn, policy=policy, lookup=lambda n, v: [], now=NOW, hub=hub)
    gone = next(x for x in r.alerts if x.artifact_id == aid)
    assert gone.severity == "high" and "removed upstream" in gone.message
    assert models.artifact_row(conn, aid).status in ("quarantined", "blocked")  # re-decided


def test_a_policy_change_re_decides_everything(hub_world, conn, policy):
    aid, _, hub, _ = hub_world
    stricter = policy.model_copy(update={"thresholds": policy.thresholds.model_copy(update={"allow": 0})})
    r = monitor.tick(conn, policy=stricter, lookup=lambda n, v: [], now=NOW, hub=hub)
    drift = next(x for x in r.alerts if "Policy changed" in x.message)
    assert stricter.version in drift.message
    assert models.latest_decision(conn, aid).policy_version == stricter.version
    assert not any("Policy changed" in x.message for x in monitor.tick(conn, policy=stricter, lookup=lambda n, v: [], now=NOW, hub=hub).alerts)


def test_a_revoked_signing_key_re_decides_what_it_signed(conn, trained, policy, apollo):
    revoked = policy.model_copy(update={"revoked_keys": [trust.key_id(apollo.public_key())]})
    r = monitor.tick(conn, policy=revoked, lookup=lambda n, v: [], now=NOW)
    assert any(a.kind == "revocation" and a.artifact_id == trained for a in r.alerts)


def test_the_scheduled_tick_runs_on_its_own(tmp_path, policy_path):
    from lineage_server import scheduler
    from lineage_server.app import create_app

    app = create_app(tmp_path / "s.db", policy_path)
    stop = scheduler.start(app, minutes=0.01)  # 0.6 s
    try:
        for _ in range(60):
            c = db.connect(tmp_path / "s.db")
            n = c.execute("SELECT COUNT(*) FROM monitor_ticks").fetchone()[0]
            c.close()
            if n:
                break
            time.sleep(0.2)
        assert n >= 1 and app.state.monitor_status["last"] is not None
        assert TestClient(app).get("/monitor/status").json()["interval_minutes"] == 0.01
    finally:
        stop.set()
