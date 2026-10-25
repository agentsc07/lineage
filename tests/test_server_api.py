import json
import shutil
import time
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from lineage.schemas.artifact import (
    ArtifactDetail, Graph, InclusionProof, IntakeJob, MerkleLog, MonitorTick, PassportReceipt, PolicyState, RevokeResult,
    StageEvent, VerifyResult,
)
from lineage.schemas.decision import Decision
from lineage.schemas.passport import SignedPassport
from lineage.schemas.policy import PolicyPack
from lineage_server import log, trust, tuf
from lineage_server.app import create_app
from tests.server_helpers import KEY, make_signed, ship_passport


@pytest.fixture
def role_keys():
    return {r: Ed25519PrivateKey.generate() for r in tuf.ROLES}


@pytest.fixture
def client(tmp_path, policy_path, role_keys):
    keys_file = tmp_path / "roles.json"
    keys_file.write_text(json.dumps({r: trust.public_hex(k.public_key()) for r, k in role_keys.items()}))
    app = create_app(tmp_path / "api.db", policy_path, keys_file)
    with TestClient(app) as c:
        yield c


def run_intake(client, kind, ref, env="dev"):
    job = IntakeJob.model_validate(client.post("/intake", json={"artifact_type": kind, "ref": str(ref), "environment": env}).json())
    r = client.get(job.events_url)  # blocks until the job is finished
    events = [StageEvent.model_validate(json.loads(l[6:])) for l in r.text.splitlines() if l.startswith("data: ")]
    return job, r, events


def test_healthz_and_lazy_app_import():
    import lineage_server.app as mod

    assert "_default_app" in vars(mod) and mod._default_app is None  # importing built nothing


def test_intake_streams_events_and_persists_artifact(client, tiny_dataset):
    job, r, events = run_intake(client, "dataset", tiny_dataset)
    assert r.headers["content-type"].startswith("text/event-stream")
    done = [e for e in events if e.status != "started"]
    assert [e.stage for e in done] == ["S1", "S2", "S3", "S4", "S5", "S6", "S7"]
    decision = next(e.decision for e in events if e.decision)
    detail = ArtifactDetail.model_validate(client.get(f"/artifacts/{decision.artifact_id}").json())
    assert detail.artifact.status == "admitted" and detail.decision == decision and detail.passport is not None
    assert [a["id"] for a in client.get("/artifacts").json()] == [decision.artifact_id]


def test_events_replay_for_late_subscriber_and_unknown_job(client, tiny_dataset):
    job, _, first = run_intake(client, "dataset", tiny_dataset)
    again = [json.loads(l[6:]) for l in client.get(job.events_url).text.splitlines() if l.startswith("data: ")]
    assert len(again) == len(first)
    assert client.get("/events/nope").status_code == 404


def test_sse_is_incremental_while_the_job_runs(client, tiny_dataset, monkeypatch):
    import threading

    from lineage.intake import inspectors as insp

    gate = threading.Event()
    monkeypatch.setitem(insp.INSPECTORS, ("dataset", "S3"), [("slow", lambda ctx: (gate.wait(5), [])[1])])
    job = IntakeJob.model_validate(client.post("/intake", json={"artifact_type": "dataset", "ref": str(tiny_dataset)}).json())
    time.sleep(0.2)
    stored = client.app.state.jobs.get(job.job_id)
    assert any(e.stage == "S3" and e.status == "started" for e in stored.events) and not stored.done  # mid-flight
    gate.set()
    text = client.get(job.events_url).text
    assert '"stage":"S7"' in text


def test_intake_rejects_unknown_environment(client, tiny_dataset):
    r = client.post("/intake", json={"artifact_type": "dataset", "ref": str(tiny_dataset), "environment": "qa"})
    assert r.status_code == 400


def test_blocked_artifact_is_still_catalogued_with_evidence(client, tmp_path):
    d = tmp_path / "m"
    d.mkdir()
    (d / "pytorch_model.bin").write_bytes(b"\x80\x04N.")
    _, _, events = run_intake(client, "model", d)
    dec = next(e.decision for e in events if e.decision)
    assert dec.outcome == "block"
    row = next(a for a in client.get("/artifacts").json() if a["id"] == dec.artifact_id)
    assert row["status"] == "blocked" and row["outcome"] == "block"


def test_unknown_artifact_graph_passport_are_404(client):
    for path in ("/artifacts/lp:x", "/graph/lp:x", "/passports/lp:x", "/passports/lp:x/verify", "/log/proof/lp:x"):
        assert client.get(path).status_code == 404
    assert client.post("/revoke/lp:x").status_code == 404
    body = {"approver": "a", "reason": "r", "expires": (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()}
    assert client.post("/decisions/lp:x/approve", json=body).status_code == 404


def test_passport_register_get_verify_and_log_proof(client):
    client.app.state  # app built
    from lineage_server import db

    conn = db.connect(client.app.state.db_path)
    trust.trust_key(conn, KEY.public_key(), "creator")
    parent = make_signed("ds", "dataset")
    child = make_signed("m", "model", parents=[parent.passport_id])

    def post(sp):
        return client.post("/passports", content=sp.model_dump_json(by_alias=True), headers={"content-type": "application/json"})

    first = PassportReceipt.model_validate(post(parent).json())
    assert first.passport_id == parent.passport_id
    receipt = PassportReceipt.model_validate(post(child).json())
    assert receipt.log_index == first.log_index + 1 and post(child).json()["log_index"] == receipt.log_index  # idempotent
    assert SignedPassport.model_validate(client.get(f"/passports/{child.passport_id}").json()) == child
    v = VerifyResult.model_validate(client.get(f"/passports/{child.passport_id}/verify").json())
    assert v.valid and v.signature_ok and v.chain_ok and not v.revoked

    proof = InclusionProof.model_validate(client.get(f"/log/proof/{child.passport_id}").json())
    assert log.verify_inclusion(proof.leaf_hash, proof.index, proof.size, proof.path, proof.root)
    assert MerkleLog.model_validate(client.get("/log").json()).root == proof.root


def test_passport_with_untrusted_or_bad_signature_rejected(client):
    outsider = make_signed("x", key=Ed25519PrivateKey.generate())
    body = outsider.model_dump_json(by_alias=True)
    assert client.post("/passports", content=body, headers={"content-type": "application/json"}).status_code == 403
    from lineage_server import db

    conn = db.connect(client.app.state.db_path)
    trust.trust_key(conn, KEY.public_key(), "creator")
    forged = make_signed("y").model_copy(update={"signature": trust.sign_bytes(b"nope", KEY)})
    assert client.post("/passports", content=forged.model_dump_json(by_alias=True), headers={"content-type": "application/json"}).status_code == 400


def test_verify_reports_missing_and_revoked_ancestors(client):
    from lineage_server import db

    conn = db.connect(client.app.state.db_path)
    trust.trust_key(conn, KEY.public_key(), "creator")
    orphan = make_signed("o", "model", parents=["lp:" + "b" * 64])
    client.post("/passports", content=orphan.model_dump_json(by_alias=True), headers={"content-type": "application/json"})
    v = client.get(f"/passports/{orphan.passport_id}/verify").json()
    assert not v["valid"] and not v["chain_ok"] and any("not registered" in p for p in v["problems"])


def test_graph_revoke_and_blast_radius_over_http(client, tmp_path, tiny_model):
    # dataset -> model (parent edge via shipped passport) -> agent
    from lineage_server import db

    conn = db.connect(client.app.state.db_path)
    trust.trust_key(conn, KEY.public_key(), "creator")
    ds = tmp_path / "ds"
    ds.mkdir()
    (ds / "data.csv").write_text("a,b\n1,2\n")
    _, _, ev = run_intake(client, "dataset", ds)
    ds_id = next(e.decision for e in ev if e.decision).artifact_id
    m = tiny_model
    ship_passport(m, parents=[ds_id])
    _, _, ev = run_intake(client, "model", m)
    m_id = next(e.decision for e in ev if e.decision).artifact_id
    a = tmp_path / "agent"
    a.mkdir()
    (a / "agent.json").write_text(json.dumps({"name": "triage", "version": "1", "parts": [m_id]}))
    _, _, ev = run_intake(client, "agent", a)
    a_id = next(e.decision for e in ev if e.decision).artifact_id

    up = Graph.model_validate(client.get(f"/graph/{a_id}", params={"direction": "up"}).json())
    assert {n.id for n in up.nodes} == {ds_id, m_id, a_id} and len(up.edges) == 2
    down = Graph.model_validate(client.get(f"/graph/{ds_id}", params={"direction": "down"}).json())
    assert down.direction == "down" and {n.id for n in down.nodes} == {ds_id, m_id, a_id}

    res = RevokeResult.model_validate(client.post(f"/revoke/{ds_id}", params={"reason": "poisoned labels"}).json())
    assert {n.id for n in res.blast_radius} == {m_id, a_id} and all(n.status == "blocked" for n in res.blast_radius)
    detail = ArtifactDetail.model_validate(client.get(f"/artifacts/{a_id}").json())
    assert detail.decision.outcome == "block" and detail.artifact.status == "blocked"
    assert client.get(f"/artifacts/{ds_id}").json()["artifact"]["status"] == "revoked"


def test_tool_quarantine_then_approve_over_http(client, toy_tool, tmp_path):
    t = tmp_path / "word_count"
    shutil.copytree(toy_tool, t)
    _, _, ev = run_intake(client, "tool", t)
    dec = next(e.decision for e in ev if e.decision)
    assert dec.outcome == "quarantine"
    expires = (datetime.now(timezone.utc) + timedelta(days=7)).isoformat()
    r = client.post(f"/decisions/{dec.artifact_id}/approve", json={"approver": "dr.rao", "reason": "code reviewed", "expires": expires})
    approved = Decision.model_validate(r.json())
    assert approved.outcome == "allow_with_conditions" and approved.approver == "dr.rao"
    assert client.get(f"/artifacts/{dec.artifact_id}").json()["artifact"]["status"] == "admitted_with_conditions"
    past = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    assert client.post(f"/decisions/{dec.artifact_id}/approve", json={"approver": "a", "reason": "r", "expires": past}).status_code == 422


def test_hard_block_cannot_be_approved(client, tmp_path):
    d = tmp_path / "m"
    d.mkdir()
    (d / "w.pt").write_bytes(b"x")
    dec = next(e.decision for e in run_intake(client, "model", d)[2] if e.decision)
    expires = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()
    r = client.post(f"/decisions/{dec.artifact_id}/approve", json={"approver": "a", "reason": "r", "expires": expires})
    assert r.status_code == 409 and r.json()["detail"]["reasons"]


# --- policy ---
def signed_update(client, role_keys, roles, mutate=None, days=90):
    state = PolicyState.model_validate(client.get("/policy").json())
    pack = PolicyPack.model_validate(state.policy).model_copy(update=mutate or {})
    exp = datetime.now(timezone.utc) + timedelta(days=days)
    return {
        "policy": pack.model_dump(mode="json"),
        "signatures": [tuf.sign_update(pack, exp, r, role_keys[r]).model_dump() for r in roles],
        "expires_at": exp.isoformat(),
    }


def test_policy_put_requires_two_of_three(client, role_keys):
    before = PolicyState.model_validate(client.get("/policy").json())
    assert before.roles_required == 2 and before.roles_total == 3
    one = client.put("/policy", json=signed_update(client, role_keys, ["owner"], {"org": "X"}))
    assert one.status_code == 403
    none = client.put("/policy", json={"policy": before.policy, "signatures": [], "expires_at": (datetime.now(timezone.utc) + timedelta(days=60)).isoformat()})
    assert none.status_code == 403
    ok = client.put("/policy", json=signed_update(client, role_keys, ["owner", "compliance"], {"org": "Apollo v2"}))
    assert ok.status_code == 200 and PolicyState.model_validate(ok.json()).policy["org"] == "Apollo v2"
    assert client.get("/policy").json()["version"] != before.version


def test_policy_put_rejects_rollback_expired_and_invalid(client, role_keys):
    assert client.put("/policy", json=signed_update(client, role_keys, ["owner", "security"], days=10)).status_code == 409  # rollback
    assert client.put("/policy", json=signed_update(client, role_keys, ["owner", "security"], days=-1)).status_code == 400  # expired
    bad = signed_update(client, role_keys, ["owner", "security"])
    bad["policy"] = {"org": "only"}
    assert client.put("/policy", json=bad).status_code == 422


def test_policy_put_disabled_without_role_keys(tmp_path, policy_path):
    with TestClient(create_app(tmp_path / "nk.db", policy_path)) as c:
        state = PolicyState.model_validate(c.get("/policy").json())
        r = c.put("/policy", json={"policy": state.policy, "signatures": [], "expires_at": (datetime.now(timezone.utc) + timedelta(days=60)).isoformat()})
        assert r.status_code == 409


def test_expired_policy_fails_closed_for_new_intake(tmp_path, policy_path, tiny_dataset):
    app = create_app(tmp_path / "e.db", policy_path)
    from lineage_server import db

    conn = db.connect(app.state.db_path)
    conn.execute("UPDATE policy_state SET expires_at = ?", ((datetime.now(timezone.utc) - timedelta(days=1)).isoformat(),))
    with TestClient(app) as c:
        _, _, events = run_intake(c, "dataset", tiny_dataset)
    dec = next(e.decision for e in events if e.decision)
    assert dec.outcome == "quarantine" and any("policy metadata has expired" in r for r in dec.reasons)


# --- monitor ---
def test_monitor_tick_endpoint_with_no_news(client):
    tick = MonitorTick.model_validate(client.post("/monitor/tick").json())
    assert tick.checked == 0 and tick.alerts == []
