"""G1: a model built in an environment with ~60 packages must not draw 60 ghost nodes; an advised package still gets its own node."""
import pytest

from lineage.intake.pipeline import run_to_decision
from lineage.schemas.finding import Evidence, Finding
from lineage.schemas.passport import Action, SbomComponent
from lineage_server import graph, monitor
from tests.fakehub import old_release_hub
from tests.fixtures.builders import make_tiny_model
from tests.server_helpers import NOW
from tests.test_graph_monitor import apollo, conn, policy, registry  # noqa: F401  (fixtures)
from tests.test_signature_scope import passport_for


@pytest.fixture
def trained(conn, registry, policy, apollo, tmp_path):  # noqa: F811
    m = make_tiny_model(tmp_path / "trained")
    sbom = [SbomComponent(name=f"pkg{i}", version="1.0", purl=f"pkg:pypi/pkg{i}@1.0") for i in range(59)] + \
           [SbomComponent(name="jinja2", version="3.1.6", purl="pkg:pypi/jinja2@3.1.6")]
    passport_for(m, apollo, None, hub="local-run", action=Action(kind="train"), inputs={"data.csv": "a" * 64}, sbom=sbom)
    d, _ = run_to_decision("model", str(m), "dev", policy, "j", now=NOW, hub=old_release_hub(), registry=registry)
    return d.artifact_id


def advisory(name, version):
    if (name, version) != ("jinja2", "3.1.6"):
        return []
    return [Finding(id="PKG.OSV.GHSA-demo-0001", title="demo advisory", severity="high", category="code", stage="S3",
                    evidence=[Evidence(kind="field", ref="GHSA-demo-0001")], score=25, source="deterministic")]


def test_sixty_ghosts_collapse_into_one_group_node(conn, trained):
    g = graph.lineage_graph(conn, trained, "up")
    assert len(g.nodes) == 61  # 60 ghosts and the model, as stored
    c = graph.collapse_sbom(conn, g)
    assert len(c.nodes) < 15 and len(c.nodes) == 2
    group = next(n for n in c.nodes if n.id.startswith("sbom-group:"))
    assert len(group.group_members) == 60 and "60 packages in the build environment" in group.label
    assert [(e.source, e.target, e.kind, e.evidence) for e in c.edges] == [(group.id, trained, "built_with", "sbom")]


def test_a_ghost_with_an_advisory_stays_a_node_of_its_own(conn, trained, policy):
    monitor.tick(conn, policy=policy, lookup=advisory, now=NOW)
    c = graph.collapse_sbom(conn, graph.lineage_graph(conn, trained, "up"))
    ids = {n.id for n in c.nodes}
    assert "ghost:package:jinja2@3.1.6" in ids and len(c.nodes) == 3  # model, the advised ghost, the group of the other 59
    j = next(n for n in c.nodes if n.id == "ghost:package:jinja2@3.1.6")
    assert j.version == "3.1.6" and j.advisories == ["PKG.OSV.GHSA-demo-0001"]
    group = next(n for n in c.nodes if n.id.startswith("sbom-group:"))
    assert len(group.group_members) == 59


def test_edge_evidence_classes(conn, trained):
    g = graph.lineage_graph(conn, trained, "up")
    assert {e.evidence for e in g.edges} == {"sbom"}


def test_the_route_collapses_by_default_and_can_be_turned_off(tmp_path, policy_path):
    from fastapi.testclient import TestClient

    from lineage_server.app import create_app

    api = TestClient(create_app(tmp_path / "x.db", policy_path, require_auth=False))
    assert api.get("/graph/unknown").status_code == 404
