"""P1.5: the SSE stream is opened with a short-lived, job-scoped ticket; the API token is never accepted from a URL."""
import json
import shutil

import pytest
from fastapi.testclient import TestClient

from lineage_server import auth, db
from lineage_server.app import create_app
from tests.fakehub import old_release_hub


@pytest.fixture
def api(tmp_path, policy_path, monkeypatch):
    monkeypatch.setenv("LINEAGE_DEV_LOCAL_PATHS", "1")
    app = create_app(tmp_path / "t.db", policy_path, hub=old_release_hub(), require_auth=True)
    conn = db.connect(tmp_path / "t.db")
    tokens = {"alice": auth.create_user(conn, "alice", "requester"), "dave": auth.create_user(conn, "dave", "auditor")}
    conn.commit()
    c = TestClient(app)
    c.tokens, c.app_ = tokens, app
    return c


def h(api, who="alice"):
    return {"Authorization": f"Bearer {api.tokens[who]}"}


@pytest.fixture
def job(api, toy_tool, tmp_path):
    t = tmp_path / "tool"
    shutil.copytree(toy_tool, t)
    r = api.post("/intake", headers=h(api), json={"artifact_type": "tool", "ref": str(t), "environment": "dev"})
    api.get(r.json()["events_url"], headers=h(api))  # let it finish
    return r.json()["job_id"]


def test_a_ticket_opens_the_stream_without_any_token(api, job):
    t = api.post(f"/jobs/{job}/stream-ticket", headers=h(api)).json()
    assert t["ticket"].startswith("st_") and t["job_id"] == job and t["expires_in"] == 60
    r = api.get(f"/events/{job}", params={"ticket": t["ticket"]})  # no Authorization header
    assert r.status_code == 200 and "data:" in r.text and json.loads(r.text.split("data: ")[1].split("\n")[0])["job_id"] == job


def test_the_api_token_in_the_url_is_not_accepted_anywhere(api, job):
    tok = api.tokens["alice"]
    assert api.get(f"/events/{job}", params={"token": tok}).status_code == 401
    assert api.get("/artifacts", params={"token": tok}).status_code == 401
    assert api.get("/artifacts", headers=h(api)).status_code == 200


def test_a_ticket_is_for_one_job_only(api, job, toy_tool, tmp_path):
    t2 = tmp_path / "tool2"
    shutil.copytree(toy_tool, t2)
    other = api.post("/intake", headers=h(api), json={"artifact_type": "tool", "ref": str(t2), "environment": "dev"}).json()["job_id"]
    ticket = api.post(f"/jobs/{job}/stream-ticket", headers=h(api)).json()["ticket"]
    assert api.get(f"/events/{other}", params={"ticket": ticket}).status_code == 401


def test_a_ticket_opens_no_other_route(api, job):
    ticket = api.post(f"/jobs/{job}/stream-ticket", headers=h(api)).json()["ticket"]
    for path in ("/artifacts", f"/jobs/{job}", "/policy", "/log"):
        assert api.get(path, params={"ticket": ticket}).status_code == 401, path
    assert api.post(f"/jobs/{job}/stream-ticket", params={"ticket": ticket}).status_code == 401  # a ticket cannot mint tickets


def test_a_ticket_expires(api, job):
    clock = {"t": 1000.0}
    api.app_.state.tickets = auth.TicketStore(seconds=60, clock=lambda: clock["t"])
    ticket = api.post(f"/jobs/{job}/stream-ticket", headers=h(api)).json()["ticket"]
    assert api.get(f"/events/{job}", params={"ticket": ticket}).status_code == 200
    clock["t"] += 61
    assert api.get(f"/events/{job}", params={"ticket": ticket}).status_code == 401


def test_a_ticket_needs_a_signed_in_user_and_a_real_job(api, job):
    assert api.post(f"/jobs/{job}/stream-ticket").status_code == 401
    assert api.post("/jobs/nope/stream-ticket", headers=h(api)).status_code == 404
    assert api.get(f"/events/{job}", params={"ticket": "st_forged"}).status_code == 401
