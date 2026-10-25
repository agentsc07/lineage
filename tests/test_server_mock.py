import json

import pytest
from fastapi.testclient import TestClient

from lineage.schemas.artifact import (
    Alert, ArtifactDetail, Graph, InclusionProof, IntakeJob, MerkleLog, MonitorTick, PassportReceipt,
    PolicyState, RevokeResult, StageEvent, VerifyResult,
)
from lineage.schemas.decision import Decision
from lineage.schemas.passport import SignedPassport
from lineage_server import mock
from lineage_server.app import app

client = TestClient(app)
MODEL = mock.MODEL_ID


def test_healthz():
    assert client.get("/healthz").json() == {"status": "ok"}


def test_intake_and_events():
    job = IntakeJob.model_validate(client.post("/intake", json={"artifact_type": "model", "ref": "x", "environment": "dev"}).json())
    r = client.get(job.events_url)
    assert r.headers["content-type"].startswith("text/event-stream")
    events = [StageEvent.model_validate(json.loads(l[6:])) for l in r.text.splitlines() if l.startswith("data: ")]
    assert [e.stage for e in events] == ["S1", "S2", "S3", "S4", "S5", "S6", "S7"]
    assert events[5].decision is not None


def test_artifacts():
    assert len(client.get("/artifacts").json()) == 3
    ArtifactDetail.model_validate(client.get(f"/artifacts/{MODEL}").json())


def test_passports():
    sp = SignedPassport.model_validate(client.get(f"/passports/{MODEL}").json())
    receipt = PassportReceipt.model_validate(client.post("/passports", content=sp.model_dump_json(by_alias=True), headers={"content-type": "application/json"}).json())
    assert receipt.passport_id == MODEL
    assert VerifyResult.model_validate(client.get(f"/passports/{MODEL}/verify").json()).valid


@pytest.mark.parametrize("direction", ["up", "down"])
def test_graph(direction):
    g = Graph.model_validate(client.get(f"/graph/{mock.DATASET_ID}", params={"direction": direction}).json())
    assert g.direction == direction and g.nodes


def test_revoke_blast_radius():
    r = RevokeResult.model_validate(client.post(f"/revoke/{mock.DATASET_ID}", params={"reason": "bad"}).json())
    assert len(r.blast_radius) == 2


def test_policy_get_put():
    state = PolicyState.model_validate(client.get("/policy").json())
    put = client.put("/policy", json={"policy": state.policy, "signatures": []})
    assert PolicyState.model_validate(put.json()).version == state.version


def test_approve():
    body = {"approver": "dr.rao", "reason": "reviewed", "expires": "2026-12-01T00:00:00Z"}
    d = Decision.model_validate(client.post(f"/decisions/{MODEL}/approve", json=body).json())
    assert d.approver == "dr.rao"


def test_log_and_monitor():
    log = MerkleLog.model_validate(client.get("/log").json())
    assert log.size == len(log.entries)
    InclusionProof.model_validate(client.get(f"/log/proof/{MODEL}").json())
    tick = MonitorTick.model_validate(client.post("/monitor/tick").json())
    assert all(isinstance(a, Alert) for a in tick.alerts)
