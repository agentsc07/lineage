"""P0.2: Reject refuses a pending request (never admitted, nothing revoked); Revoke withdraws an admitted artifact and re-evaluates descendants."""
import json
import shutil
import sqlite3
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from lineage_server import auth, db
from lineage_server.app import create_app
from tests.fakehub import old_release_hub
from tests.fixtures.builders import make_tiny_model


@pytest.fixture
def api(tmp_path, policy_path):
    app = create_app(tmp_path / "r.db", policy_path, hub=old_release_hub(), require_auth=True)
    conn = db.connect(tmp_path / "r.db")
    tokens = {n: auth.create_user(conn, n, r, f"{n}@x") for n, r in [("alice", "requester"), ("bob", "approver"), ("dave", "auditor")]}
    conn.commit()
    c = TestClient(app)
    c.tokens, c.db = tokens, tmp_path / "r.db"
    return c


def h(api, who):
    return {"Authorization": f"Bearer {api.tokens[who]}"}


def intake(api, who, kind, ref, env="dev"):
    r = api.post("/intake", headers=h(api, who), json={"artifact_type": kind, "ref": str(ref), "environment": env})
    assert r.status_code == 200, r.text
    ev = [json.loads(e) for e in api.get(r.json()["events_url"], headers=h(api, who)).text.split("data: ")[1:]]
    return next(e["decision"] for e in ev if e.get("decision"))


@pytest.fixture(autouse=True)
def dev_paths(monkeypatch):
    monkeypatch.setenv("LINEAGE_DEV_LOCAL_PATHS", "1")


@pytest.fixture
def pending(api, toy_tool, tmp_path):
    t = tmp_path / "tool"
    shutil.copytree(toy_tool, t)
    d = intake(api, "alice", "tool", t)
    assert d["outcome"] == "quarantine"  # a tool always needs a human
    return d["artifact_id"]


def reject(api, who, aid, reason="not needed by any team"):
    return api.post(f"/decisions/{aid}/reject", headers=h(api, who), json={"reason": reason})


def rows(api, sql, *a):
    c = sqlite3.connect(api.db)
    c.row_factory = sqlite3.Row
    return c.execute(sql, a).fetchall()


def test_an_approver_rejects_a_pending_request_and_nothing_is_revoked(api, pending):
    r = reject(api, "bob", pending)
    assert r.status_code == 200 and r.json()["status"] == "rejected" and r.json()["actor"] == "bob"
    assert api.get(f"/artifacts/{pending}", headers=h(api, "bob")).json()["artifact"]["status"] == "rejected"
    assert not rows(api, "SELECT 1 FROM revocations WHERE artifact_id = ?", pending)        # not a revocation
    rj = rows(api, "SELECT actor, reason FROM rejections WHERE artifact_id = ?", pending)
    assert [(x["actor"], x["reason"]) for x in rj] == [("bob", "not needed by any team")]   # actor and reason recorded
    assert rows(api, "SELECT 1 FROM decisions WHERE artifact_id = ?", pending)              # the decision history is kept
    assert "rejection" in {e["kind"] for e in api.get("/log", headers=h(api, "bob")).json()["entries"]}
    att = api.get(f"/attestations/{pending}?env=dev", headers=h(api, "bob")).json()["attestation"]
    assert att["outcome"] == "block" and att["revoked"] is False                            # unusable, and still not "revoked"


def test_the_requester_cannot_reject_their_own_request_and_a_requester_or_auditor_cannot_reject_at_all(api, pending):
    assert reject(api, "alice", pending).status_code == 403
    assert reject(api, "dave", pending).status_code == 403
    assert api.get(f"/artifacts/{pending}", headers=h(api, "bob")).json()["artifact"]["status"] == "quarantined"


def test_a_rejected_request_cannot_be_rejected_again_or_approved(api, pending):
    assert reject(api, "bob", pending).status_code == 200
    assert reject(api, "bob", pending).status_code == 409
    exp = (datetime.now(timezone.utc) + timedelta(days=3)).isoformat()
    # a second approver is needed for separation of duties; bob is not the requester so he may try
    r = api.post(f"/decisions/{pending}/approve", headers=h(api, "bob"), json={"reason": "changed my mind", "expires": exp})
    assert r.status_code == 409 and "rejected" in json.dumps(r.json())


def test_a_pending_request_cannot_be_revoked_it_was_never_admitted(api, pending):
    r = api.post(f"/revoke/{pending}?reason=x", headers=h(api, "bob"))
    assert r.status_code == 409 and "never admitted" in r.text and "reject" in r.text


def test_an_admitted_artifact_cannot_be_rejected_but_can_be_revoked(api, tmp_path):
    d = intake(api, "alice", "model", make_tiny_model(tmp_path / "m"))
    assert d["outcome"] == "allow"
    r = reject(api, "bob", d["artifact_id"])
    assert r.status_code == 409 and "use revoke" in r.text
    v = api.post(f"/revoke/{d['artifact_id']}?reason=bad", headers=h(api, "bob"))
    assert v.status_code == 200 and v.json()["revoked"] == d["artifact_id"]
    assert rows(api, "SELECT 1 FROM revocations WHERE artifact_id = ?", d["artifact_id"])
    assert not rows(api, "SELECT 1 FROM rejections WHERE artifact_id = ?", d["artifact_id"])


def test_a_hard_block_is_not_a_pending_request_and_still_cannot_be_approved_away(api, tmp_path):
    from tests.fixtures.builders import make_malicious_pickle

    p = tmp_path / "evil"
    p.mkdir()
    make_malicious_pickle(p / "model.pkl")
    d = intake(api, "alice", "model", p)
    assert d["outcome"] == "block"
    assert reject(api, "bob", d["artifact_id"]).status_code == 409
    exp = (datetime.now(timezone.utc) + timedelta(days=3)).isoformat()
    assert api.post(f"/decisions/{d['artifact_id']}/approve", headers=h(api, "bob"), json={"reason": "please", "expires": exp}).status_code == 409


def test_an_unknown_artifact_is_a_404(api):
    assert reject(api, "bob", "lp:nope").status_code == 404
