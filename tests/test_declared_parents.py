"""Parents the uploader declares (form field `parents`, or `"parents"` in lineage.meta.json), and the name of a row whose hub fetch failed."""
import json

from tests.test_intake_page_api import hubroot, make_api, zipped  # noqa: F401  (fixtures)
import shutil


def upload(api, tmp_path, hubroot, tag, claims, meta=None):
    up = tmp_path / f"up-{tag}"
    shutil.copytree(hubroot / "models" / "acme" / "tiny", up)
    if meta is not None:
        (up / "lineage.meta.json").write_text(json.dumps(meta))
    z = zipped(up, tmp_path / f"{tag}.zip")
    uid = api.post("/uploads", files={"file": (f"{tag}.zip", z.read_bytes())}).json()["upload_id"]
    job = api.post("/intake", json={"artifact_type": "model", "source": f"upload:{uid}", "environment": "dev", "claims": claims}).json()
    events = [json.loads(e) for e in api.get(job["events_url"]).text.split("data: ")[1:]]
    aid = next(e["decision"] for e in events if e.get("decision"))["artifact_id"]
    return aid, api.get(f"/artifacts/{aid}").json()


def ids(detail):
    return {f["id"] for f in detail["findings"]}


def test_a_declared_parent_in_the_registry_becomes_a_parent_and_an_edge(tmp_path, policy_path, hubroot):
    api = make_api(tmp_path, policy_path, hubroot)
    base_id, _ = upload(api, tmp_path, hubroot, "base", {"name": "base-model", "version": "1.0"})
    child_id, child = upload(api, tmp_path, hubroot, "child", {"name": "child", "version": "0.1", "parents": "base-model@1.0"})
    assert "PROV.PARENT.DECLARED" in ids(child) and "PROV.PARENT.UNRESOLVED" not in ids(child)
    assert base_id in child["passport"]["passport"]["predicate"]["parents"]
    g = api.get(f"/graph/{child_id}").json()
    assert any(e["source"] == base_id and e["target"] == child_id and e["kind"] == "derived_from" for e in g["edges"])


def test_a_declared_parent_by_id_and_from_the_meta_file(tmp_path, policy_path, hubroot):
    api = make_api(tmp_path, policy_path, hubroot)
    base_id, _ = upload(api, tmp_path, hubroot, "base", {"name": "base-model", "version": "1.0"})
    _, by_id = upload(api, tmp_path, hubroot, "c1", {"name": "c1", "version": "1", "parents": base_id})
    _, by_meta = upload(api, tmp_path, hubroot, "c2", {"name": "c2", "version": "1"}, meta={"parents": ["base-model@1.0"]})
    for d in (by_id, by_meta):
        assert base_id in d["passport"]["passport"]["predicate"]["parents"]


def test_a_declared_parent_that_does_not_exist_is_flagged_and_drawn_as_unregistered(tmp_path, policy_path, hubroot):
    api = make_api(tmp_path, policy_path, hubroot)
    child_id, child = upload(api, tmp_path, hubroot, "child", {"name": "child", "version": "1", "parents": "nothing-here@9"})
    assert "PROV.PARENT.UNRESOLVED" in ids(child) and child["passport"]["passport"]["predicate"]["parents"] == []
    g = api.get(f"/graph/{child_id}").json()
    assert any(n["status"] == "unregistered" and "nothing-here" in n["label"] for n in g["nodes"])


def test_a_declared_parent_can_only_add_risk(tmp_path, policy_path, hubroot):
    api = make_api(tmp_path, policy_path, hubroot)
    _, plain = upload(api, tmp_path, hubroot, "p0", {"name": "p0", "version": "1"})
    base_id, _ = upload(api, tmp_path, hubroot, "base", {"name": "base-model", "version": "1.0"})
    _, with_parent = upload(api, tmp_path, hubroot, "p1", {"name": "p1", "version": "1", "parents": "base-model@1.0"})
    _, with_ghost = upload(api, tmp_path, hubroot, "p2", {"name": "p2", "version": "1", "parents": "nothing-here@9"})
    assert with_parent["artifact"]["risk_score"] >= plain["artifact"]["risk_score"]
    assert with_ghost["artifact"]["risk_score"] > plain["artifact"]["risk_score"]


def test_a_failed_fetch_is_recorded_under_the_name_that_was_asked_for(tmp_path, policy_path, hubroot):
    api = make_api(tmp_path, policy_path, hubroot)
    for src, typ, name, version in [("pypi:nothing-here==1.2.3", "package", "nothing-here", "1.2.3"),
                                    ("hf-dataset:org/notes", "dataset", "org/notes", "unresolved")]:
        job = api.post("/intake", json={"artifact_type": typ, "source": src, "environment": "prod"}).json()
        events = [json.loads(e) for e in api.get(job["events_url"]).text.split("data: ")[1:]]
        aid = next(e["decision"] for e in events if e.get("decision"))["artifact_id"]
        a = api.get(f"/artifacts/{aid}").json()["artifact"]
        assert (a["name"], a["version"]) == (name, version)


def test_the_view_reports_the_creator_passport_fields_and_facts_are_not_duplicated(tmp_path, policy_path, hubroot):
    api = make_api(tmp_path, policy_path, hubroot)
    aid, detail = upload(api, tmp_path, hubroot, "plain", {"name": "plain", "version": "1"})
    v = api.get(f"/artifacts/{aid}/view").json()
    assert v["creator_passport"] == {"present": False}
    keys = [(f["key"], f["value"], f["provenance"], f["source"]) for f in detail["passport"]["passport"]["predicate"]["facts"]]
    assert len(keys) == len(set(keys))
