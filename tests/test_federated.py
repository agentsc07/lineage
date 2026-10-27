"""R3.3 / test 11 (and test 7's client part): the federated gate (REFACTOR_SPEC 8.6)."""
import base64
import io

import numpy as np
import pytest
from fastapi.testclient import TestClient

from bench.fl_bench import simulate
from lineage.federated import scoring
from lineage.federated.aggregate import aggregate
from lineage.federated.gate import ClientState, process_round, update_trust
from lineage.federated.secure_agg import mask_update, norm_consistent, unmask_sum
from lineage_server.app import create_app
from tests.fakehub import old_release_hub
from tests.fixtures.builders import make_tiny_model


def test_scaling_attack_trust_weighted_stays_within_3_points_and_fedavg_collapses():
    clean = simulate(None, 0, "fedavg", seed=1)["accuracy"]
    fedavg = simulate("scaling_x10", 4, "fedavg", seed=1)["accuracy"]
    gated = simulate("scaling_x10", 4, "trust_weighted", seed=1)
    assert clean - gated["accuracy"] <= 0.03, (clean, gated)
    assert clean - fedavg > 0.10, (clean, fedavg)
    assert gated["recall"] == 1.0 and gated["quarantined_attackers"] == 4


def test_scores_single_out_a_scaled_update():
    rng = np.random.default_rng(0)
    U = rng.normal(0, 1, (10, 50)) + 1.0
    U[3] *= 10
    z = scoring.robust_z(scoring.l2_norms(U))
    assert z.argmax() == 3 and z[3] > 3 and (np.delete(z, 3) < 3).all()


def test_aggregators_resist_outliers_where_fedavg_does_not():
    U = np.vstack([np.ones((9, 5)), 1000 * np.ones((1, 5))])
    assert aggregate("fedavg", U)[0] > 50
    assert aggregate("median", U)[0] == 1 and aggregate("trimmed_mean", U)[0] == pytest.approx(1.0) and aggregate("multi_krum", U, f=1)[0] == 1
    assert aggregate("trust_weighted", U, weights=np.array([1] * 9 + [0.0]))[0] == 1


def test_client_trust_rule_and_quarantine():
    st = ClientState("c")
    update_trust(st, True, ["x"])
    assert st.trust == 0.5 and not st.quarantined
    update_trust(st, False, [])
    assert st.trust == pytest.approx(0.55)
    for _ in range(3):
        update_trust(st, True, ["x"])
    assert st.trust < 0.3 and st.quarantined
    ok = ClientState("d")
    for _ in range(5):
        update_trust(ok, False, [])
    assert ok.trust == 1.0  # capped


def test_quarantined_clients_are_excluded_from_later_rounds():
    rng = np.random.default_rng(1)
    states = {}
    for r in range(6):
        ups = {f"h{i}": rng.normal(0, 1, 30) + 1 for i in range(8)}
        ups["evil"] = -50 * np.ones(30)
        res = process_round(ups, states, f=1)
        assert "evil" in res.flagged or "evil" in res.excluded
    assert states["evil"].quarantined and "evil" in res.excluded
    # with z > 3 on four scores, an honest client is occasionally flagged by chance (the benchmark reports this); it must stay rare
    assert sum(states[f"h{i}"].quarantined for i in range(8)) <= 1
    assert np.mean([states[f"h{i}"].trust for i in range(8)]) > 0.7 > states["evil"].trust


def test_secure_aggregation_masks_cancel_and_the_norm_surrogate_catches_a_lie():
    rng = np.random.default_rng(2)
    U = rng.normal(0, 1, (5, 20))
    masked = np.stack([mask_update(U[i], i, 5, b"k") for i in range(5)])
    assert not np.allclose(masked[0], U[0])  # the server sees noise
    assert np.allclose(unmask_sum(masked), U.sum(0))
    honest = np.linalg.norm(U, axis=1)
    assert norm_consistent(masked, honest)
    assert not norm_consistent(np.stack([mask_update(U[i] * (100 if i == 0 else 1), i, 5, b"k") for i in range(5)]), honest)
    res = process_round({str(i): masked[i] for i in range(5)}, {}, secure=True, claimed_norms={str(i): honest[i] for i in range(5)}, max_norm=100)
    assert res.mode == "secure_aggregation" and res.scores == {}  # no per-client scores under secure aggregation


# --- the API ---
def npz(a):
    b = io.BytesIO()
    np.savez_compressed(b, delta=a)
    return base64.b64encode(b.getvalue()).decode()


@pytest.fixture
def api(tmp_path, policy_path):
    c = TestClient(create_app(tmp_path / "f.db", policy_path, hub=old_release_hub()))
    job = c.post("/intake", json={"artifact_type": "model", "ref": str(make_tiny_model(tmp_path / "global")), "environment": "dev"}).json()
    import json

    d = next(json.loads(e)["decision"] for e in c.get(job["events_url"]).text.split("data: ")[1:] if json.loads(e).get("decision"))
    c.model_id = d["artifact_id"]
    return c


def round_body(api, rid, evil=True):
    rng = np.random.default_rng(__import__("zlib").crc32(rid.encode()) % 1000)
    ups = [{"client_id": f"h{i}", "inline": npz(rng.normal(0, 1, 40) + 1)} for i in range(8)]
    ups.append({"client_id": "evil", "inline": npz(-80 * np.ones(40) if evil else rng.normal(0, 1, 40) + 1)})
    return {"round_id": rid, "global_model_id": api.model_id, "updates": ups}


def test_round_api_flags_quarantines_and_links_the_client_to_the_global_model(api):
    for r in range(5):
        out = api.post("/fl/rounds", json=round_body(api, f"r{r}")).json()
    assert "evil" in out["flagged"] or "evil" in out["excluded"]
    clients = {c["client_id"]: c for c in api.get("/fl/clients").json()}
    assert clients["evil"]["quarantined"] and clients["evil"]["trust"] < 0.3 and not clients["h0"]["quarantined"]
    assert api.get("/fl/rounds/r0").json()["round_id"] == "r0"
    assert api.post("/fl/rounds", json=round_body(api, "r0")).status_code == 409
    g = api.get(f"/graph/{api.model_id}", params={"direction": "up"}).json()
    assert {e["kind"] for e in g["edges"]} == {"contributed_to"} and "ghost:fl-client:evil" in {n["id"] for n in g["nodes"]}


def test_revoking_a_client_flags_the_global_model_it_fed(api):
    api.post("/fl/rounds", json=round_body(api, "r0"))
    r = api.post("/revoke/ghost:fl-client:evil?reason=poisoning")
    assert r.status_code == 200 and [n["id"] for n in r.json()["blast_radius"]] == [api.model_id]
    assert api.get(f"/artifacts/{api.model_id}").json()["artifact"]["status"] in ("blocked", "quarantined")


def test_unknown_global_model_and_ragged_updates_are_refused(api):
    body = round_body(api, "bad")
    assert api.post("/fl/rounds", json={**body, "global_model_id": "lp:nope"}).status_code == 404
    body["updates"][0]["inline"] = npz(np.zeros(3))
    assert api.post("/fl/rounds", json={**body, "round_id": "bad2"}).status_code == 422
