"""Block 2: what the dashboard's intake page reads. Per-stage timings in the events, job recovery after a restart, the persisted identity
(per-file comparison with the claimed origin, facts with provenance), the artifact view, the attestation view, the pull command."""
import json
import shutil
import sqlite3
import zipfile

import pytest
from fastapi.testclient import TestClient

from lineage.intake.hub import HttpHub
from lineage_server.app import create_app
from tests.fakehub import create_app as fakehub_app
from tests.fixtures.builders import make_tiny_model

REPO = "acme/tiny"


@pytest.fixture
def hubroot(tmp_path):
    root = tmp_path / "hub"
    make_tiny_model(root / "models" / "acme" / "tiny")
    (root / "models" / "acme" / "tiny" / "README.md").write_text("---\nlicense: mit\n---\n# tiny\n")
    return root


def make_api(tmp_path, policy_path, hubroot):
    records = {f"hf:{REPO}": {"released_at": "2025-01-01T00:00:00Z", "licence": "mit"}}
    hub = HttpHub(base_url="http://testserver", client=TestClient(fakehub_app(hubroot, records)), trusted_local=False)
    return TestClient(create_app(tmp_path / "p.db", policy_path, hub=hub, require_auth=False))


def zipped(src, dest):
    with zipfile.ZipFile(dest, "w") as z:
        for p in sorted(src.rglob("*")):
            if p.is_file():
                z.write(p, p.relative_to(src).as_posix())
    return dest


def submit(api, tmp_path, hubroot, *, change=False, env="prod", claim=True, kind="model"):
    up = tmp_path / "up"
    shutil.copytree(hubroot / "models" / "acme" / "tiny", up, dirs_exist_ok=True)
    if change:
        b = bytearray((up / "model.safetensors").read_bytes())
        b[-1] ^= 0xFF
        (up / "model.safetensors").write_bytes(bytes(b))
    z = zipped(up, tmp_path / "tiny.zip")
    uid = api.post("/uploads", files={"file": ("tiny.zip", z.read_bytes())}).json()["upload_id"]
    body = {"artifact_type": kind, "source": f"upload:{uid}", "environment": env}
    if claim:
        body["claimed_origin"] = f"hf:{REPO}"
    job = api.post("/intake", json=body).json()
    events = [json.loads(e) for e in api.get(job["events_url"]).text.split("data: ")[1:]]
    return job["job_id"], events, next(e["decision"] for e in events if e.get("decision"))


def test_events_carry_the_server_measured_time_of_each_finished_stage(tmp_path, policy_path, hubroot):
    api = make_api(tmp_path, policy_path, hubroot)
    _, events, _ = submit(api, tmp_path, hubroot)
    finished = [e for e in events if e["status"] != "started"]
    assert [e["stage"] for e in finished] == ["S0", "S1", "S2", "S3", "S4", "S5", "S6", "S7"]
    assert all(e["elapsed_ms"] is not None and e["elapsed_ms"] >= 0 for e in finished)
    assert all(e["elapsed_ms"] is None for e in events if e["status"] == "started")


def test_the_view_marks_the_changed_file_against_the_claimed_origin(tmp_path, policy_path, hubroot):
    api = make_api(tmp_path, policy_path, hubroot)
    _, _, d = submit(api, tmp_path, hubroot, change=True)
    v = api.get(f"/artifacts/{d['artifact_id']}/view").json()
    by = {f["path"]: f for f in v["files"]}
    assert by["model.safetensors"]["origin"] == "changed" and by["config.json"]["origin"] == "matching"
    assert all(f["sha256"] and f["size"] for f in v["files"]) and v["merkle_root"] and v["claimed_origin"] == f"hf:{REPO}"
    assert v["hard_block"] is True and "no approval can change this" in v["next_action"] and v["pull_command"] is None
    assert v["finding_classes"]["PROV.ORIGIN.MODIFIED"] == "hard_block"
    assert {f["provenance"] for f in v["facts"]} <= {"computed", "fetched", "signed", "declared"}


def test_a_matching_upload_is_all_matching_and_dev_admits_it_with_a_pull_command(tmp_path, policy_path, hubroot):
    api = make_api(tmp_path, policy_path, hubroot)
    _, _, d = submit(api, tmp_path, hubroot, env="dev")
    v = api.get(f"/artifacts/{d['artifact_id']}/view").json()
    assert d["outcome"] == "allow" and {f["origin"] for f in v["files"]} == {"matching"} and v["origin_checked"]
    assert v["pull_command"].startswith(f"lineage pull {d['artifact_id']} ./admitted/") and " -e dev " in v["pull_command"] and "--pin" not in v["pull_command"]
    assert "--pin" in v["pull_command_first_use"] and "lg_" not in v["pull_command"]  # never a token


def test_no_claim_is_unchecked_and_says_so(tmp_path, policy_path, hubroot):
    api = make_api(tmp_path, policy_path, hubroot)
    _, _, d = submit(api, tmp_path, hubroot, claim=False, env="dev")
    v = api.get(f"/artifacts/{d['artifact_id']}/view").json()
    assert {f["origin"] for f in v["files"]} == {"unchecked"} and v["origin_checked"] is False and v["creator_passport"] == {"present": False}


def test_the_generated_pull_command_parses_with_the_real_cli(tmp_path, policy_path, hubroot):
    import shlex

    import typer.main

    from lineage.cli import app as cli_app

    api = make_api(tmp_path, policy_path, hubroot)
    _, _, d = submit(api, tmp_path, hubroot, env="dev")
    v = api.get(f"/artifacts/{d['artifact_id']}/view").json()
    pull = typer.main.get_command(cli_app).commands["pull"]
    for line, pinned in ((v["pull_command"], False), (v["pull_command_first_use"], True)):
        argv = shlex.split(line)
        assert argv[:2] == ["lineage", "pull"]
        ctx = pull.make_context("pull", argv[2:], resilient_parsing=False)
        assert ctx.params["ref"] == d["artifact_id"] and ctx.params["env"] == "dev" and ctx.params["pin"] is pinned
        assert ctx.params["server"] == "http://testserver" and str(ctx.params["dest"]) == "./admitted/tiny"


def test_a_job_is_rebuilt_from_sqlite_after_a_restart(tmp_path, policy_path, hubroot):
    api = make_api(tmp_path, policy_path, hubroot)
    job_id, events, d = submit(api, tmp_path, hubroot, env="dev")
    again = TestClient(create_app(tmp_path / "p.db", policy_path, require_auth=False))  # a new process on the same database
    replay = [json.loads(e) for e in again.get(f"/events/{job_id}").text.split("data: ")[1:]]
    assert [(e["stage"], e["status"]) for e in replay] == [(e["stage"], e["status"]) for e in events]
    j = again.get(f"/jobs/{job_id}").json()
    assert j["done"] is True and j["artifact_id"] == d["artifact_id"] and j["environment"] == "dev" and j["artifact_type"] == "model"


def test_a_job_that_was_running_when_the_server_stopped_is_reported_as_interrupted(tmp_path, policy_path):
    api = TestClient(create_app(tmp_path / "q.db", policy_path, require_auth=False))
    c = sqlite3.connect(tmp_path / "q.db")
    c.execute("INSERT INTO jobs (job_id, requester, artifact_type, environment, label, created_at, done) VALUES ('dead', 'a', 'model', 'dev', 'x', 'now', 0)")
    c.execute("INSERT INTO job_events (job_id, body) VALUES ('dead', ?)", (json.dumps({"job_id": "dead", "stage": "S0", "name": "Acquire", "status": "started",
                                                                                         "findings": [], "message": "", "decision": None, "elapsed_ms": None, "ts": "2026-10-27T10:00:00Z"}),))
    c.commit()
    events = [json.loads(e) for e in api.get("/events/dead").text.split("data: ")[1:]]
    assert events[-1]["status"] == "failed" and "interrupted" in events[-1]["message"]
    assert api.get("/events/unknown-job").status_code == 404


def test_limits_report_the_servers_real_caps(tmp_path, policy_path, monkeypatch):
    monkeypatch.setenv("LINEAGE_MAX_UPLOAD_MB", "7")
    api = TestClient(create_app(tmp_path / "l.db", policy_path, require_auth=False))
    assert api.get("/limits").json()["max_upload_mb"] == 7


def test_attestation_view_reports_the_signature_check_and_the_decision(tmp_path, policy_path, hubroot):
    api = make_api(tmp_path, policy_path, hubroot)
    _, _, d = submit(api, tmp_path, hubroot, env="dev")
    v = api.get(f"/attestations/{d['artifact_id']}/view?env=dev").json()
    assert v["signature_ok"] is True and v["attestation"]["attestation"]["outcome"] == "allow" and v["registry_key_id"] == v["attestation"]["key_id"]


def test_the_creator_passport_report_separates_signature_key_and_bytes(tmp_path, policy_path, hubroot):
    """A passport signed with an unknown key: signature not checked, key not a trusted publisher, bytes compared."""
    from tests.test_signature_scope import passport_for
    from lineage_server import trust

    key = trust.load_or_create_key(tmp_path / "attacker.key")
    up = tmp_path / "pp"
    shutil.copytree(hubroot / "models" / "acme" / "tiny", up)
    passport_for(up, key, "meta-llama/Llama-3")  # a false publisher claim signed with the attacker's own key
    z = zipped(up, tmp_path / "pp.zip")
    api = make_api(tmp_path, policy_path, hubroot)
    uid = api.post("/uploads", files={"file": ("pp.zip", z.read_bytes())}).json()["upload_id"]
    job = api.post("/intake", json={"artifact_type": "model", "source": f"upload:{uid}", "environment": "dev"}).json()
    events = [json.loads(e) for e in api.get(job["events_url"]).text.split("data: ")[1:]]
    aid = next(e["decision"]["artifact_id"] for e in events if e.get("decision"))
    cp = api.get(f"/artifacts/{aid}/view").json()["creator_passport"]
    assert cp["present"] and cp["claimed_publisher"] == "meta-llama/Llama-3" and cp["signature"] == "not_checked"
    assert cp["key_status"] == "not_a_trusted_publisher" and cp["bytes_match"] is True


def test_the_view_reports_the_status_and_says_who_rejected(tmp_path, policy_path, hubroot):
    api = make_api(tmp_path, policy_path, hubroot)
    _, _, d = submit(api, tmp_path, hubroot, env="staging")  # a clean copy that still needs a human
    v = api.get(f"/artifacts/{d['artifact_id']}/view").json()
    assert v["status"] == "quarantined"
    assert api.post(f"/decisions/{d['artifact_id']}/reject", json={"reason": "duplicate of an admitted model"}).status_code == 200
    v = api.get(f"/artifacts/{d['artifact_id']}/view").json()
    assert v["status"] == "rejected" and "Rejected by" in v["next_action"] and "duplicate of an admitted model" in v["next_action"] and v["pull_command"] is None


def test_hf_prefix_follows_the_artifact_type():
    from lineage.intake.fetch import normalise_source

    assert normalise_source("dataset", "hf:nvidia/simready-assets") == "hf-dataset:nvidia/simready-assets"
    assert normalise_source("model", "hf-dataset:org/x@abc") == "hf:org/x@abc"
    assert normalise_source("model", "hf:org/m") == "hf:org/m" and normalise_source("package", "pypi:x==1") == "pypi:x==1" and normalise_source("model", None) is None
