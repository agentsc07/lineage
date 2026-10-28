"""R2.8 / test 8: tokens, roles and separation of duties (REFACTOR_SPEC 7.1)."""
import json
import shutil
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from lineage_server import auth, db
from lineage_server.app import create_app
from tests.fakehub import old_release_hub


@pytest.fixture
def api(tmp_path, policy_path):
    app = create_app(tmp_path / "r.db", policy_path, hub=old_release_hub(), require_auth=True)
    conn = db.connect(tmp_path / "r.db")
    tokens = {n: auth.create_user(conn, n, r, f"{n}@apollo.health") for n, r in
              [("alice", "requester"), ("bob", "approver"), ("carol", "admin"), ("dave", "auditor"), ("erin", "requester,approver")]}
    conn.commit()
    c = TestClient(app)
    c.tokens = tokens
    return c


def h(api, who):
    return {"Authorization": f"Bearer {api.tokens[who]}"}


def run_tool(api, who, toy_tool, tmp_path):
    t = tmp_path / "word_count"
    shutil.copytree(toy_tool, t)
    r = api.post("/intake", headers=h(api, who), json={"artifact_type": "tool", "ref": str(t), "environment": "dev"})
    assert r.status_code == 200, r.text
    events = [json.loads(e) for e in api.get(r.json()["events_url"], headers=h(api, who)).text.split("data: ")[1:]]
    return next(e["decision"] for e in events if e.get("decision"))


def approve(api, who, aid):
    exp = (datetime.now(timezone.utc) + timedelta(days=3)).isoformat()
    return api.post(f"/decisions/{aid}/approve", headers=h(api, who), json={"reason": "reviewed", "expires": exp, "approver": "someone else"})


def test_every_endpoint_but_healthz_needs_a_token(api):
    assert api.get("/healthz").status_code == 200
    assert api.get("/artifacts").status_code == 401
    assert api.get("/artifacts", headers={"Authorization": "Bearer nope"}).status_code == 401
    assert api.get("/artifacts", headers=h(api, "dave")).status_code == 200  # an auditor reads


def test_self_approval_is_refused(api, toy_tool, tmp_path):
    d = run_tool(api, "erin", toy_tool, tmp_path)  # erin is both requester and approver
    assert d["outcome"] == "quarantine"
    r = approve(api, "erin", d["artifact_id"])
    assert r.status_code == 403 and "separation of duties" in r.json()["detail"]


def test_a_requester_cannot_approve(api, toy_tool, tmp_path):
    d = run_tool(api, "alice", toy_tool, tmp_path)
    r = approve(api, "alice", d["artifact_id"])
    assert r.status_code == 403 and "requires role approver" in r.json()["detail"]


def test_an_auditor_cannot_start_an_intake(api, toy_tool, tmp_path):
    r = api.post("/intake", headers=h(api, "dave"), json={"artifact_type": "tool", "ref": str(toy_tool), "environment": "dev"})
    assert r.status_code == 403


def test_another_approver_approves_and_the_identity_is_recorded_not_typed(api, toy_tool, tmp_path):
    d = run_tool(api, "alice", toy_tool, tmp_path)
    r = approve(api, "bob", d["artifact_id"])
    assert r.status_code == 200 and r.json()["outcome"] == "allow_with_conditions"
    assert r.json()["approver"] == "bob"  # the typed "someone else" was ignored
    detail = api.get(f"/artifacts/{d['artifact_id']}", headers=h(api, "dave")).json()
    assert detail["decision"]["approver"] == "bob"


def test_only_an_admin_changes_policy(api):
    assert api.put("/policy", headers=h(api, "bob"), json={"policy": {}}).status_code == 403
    assert api.put("/policy", headers=h(api, "carol"), json={"policy": {}}).status_code != 403


def test_token_is_stored_hashed(api, tmp_path):
    conn = db.connect(tmp_path / "r.db")
    stored = {r["token_hash"] for r in conn.execute("SELECT token_hash FROM users")}
    assert api.tokens["alice"] not in stored and auth.hash_token(api.tokens["alice"]) in stored


def test_free_text_ref_is_refused_without_the_dev_flag(api, toy_tool, monkeypatch):
    monkeypatch.delenv("LINEAGE_DEV_LOCAL_PATHS")
    r = api.post("/intake", headers=h(api, "alice"), json={"artifact_type": "tool", "ref": str(toy_tool), "environment": "dev"})
    assert r.status_code == 400 and "upload the artifact" in r.json()["detail"]


def test_upload_then_intake_by_source(api, tmp_path, monkeypatch):
    monkeypatch.delenv("LINEAGE_DEV_LOCAL_PATHS")
    api.app.state.hub = None  # a real upload: no hub vouches for it
    csv = "id,text,label\n" + "".join(f"{i},some note number {i},{i % 2}\n" for i in range(12))
    up = api.post("/uploads", headers=h(api, "alice"), files={"file": ("notes.csv", csv.encode())})
    assert up.status_code == 200 and up.json()["size"] == len(csv)
    r = api.post("/intake", headers=h(api, "alice"), json={"artifact_type": "dataset", "source": f"upload:{up.json()['upload_id']}",
                                                         "environment": "dev", "claims": {"licence": "mit"}})
    assert r.status_code == 200
    events = [json.loads(e) for e in api.get(r.json()["events_url"], headers=h(api, "alice")).text.split("data: ")[1:]]
    d = next(e["decision"] for e in events if e.get("decision"))
    ids = {f["id"] for f in d["findings"]}
    assert "PROV.ORIGIN.UNCLAIMED" in ids and d["trust_level"] == "unknown"
    # the uploader's licence claim is declared: allowed, but only declared
    assert "POLICY.LICENCE.UNVERIFIED" in ids
    # and the exact bytes are in the content-addressed store
    assert any((tmp_path / "lineage-store" / "blobs").rglob("*"))


def test_upload_zip_with_path_traversal_is_rejected_at_intake(api, tmp_path, monkeypatch):
    import io
    import zipfile

    monkeypatch.delenv("LINEAGE_DEV_LOCAL_PATHS")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("../evil.txt", "x")
    up = api.post("/uploads", headers=h(api, "alice"), files={"file": ("d.zip", buf.getvalue())})
    r = api.post("/intake", headers=h(api, "alice"), json={"artifact_type": "dataset", "source": f"upload:{up.json()['upload_id']}"})
    assert r.status_code == 400 and "unsafe path" in r.json()["detail"]


def test_upload_size_cap(api, monkeypatch):
    monkeypatch.setenv("LINEAGE_MAX_UPLOAD_MB", "1")
    r = api.post("/uploads", headers=h(api, "alice"), files={"file": ("big.bin", b"x" * (2 * 1024 * 1024))})
    assert r.status_code == 413
