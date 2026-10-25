import json
from datetime import datetime, timezone

from lineage.schemas import Decision, Finding, Passport, PolicyPack, SignedPassport, canonical_json
from lineage.schemas.artifact import ArtifactDetail
from lineage.schemas.finding import Evidence
from lineage_server import mock


def test_finding_roundtrip():
    f = Finding(
        id="MODEL.PICKLE.DANGEROUS_GLOBAL", title="x", severity="critical", category="model", stage="S3",
        evidence=[Evidence(kind="file_line", ref="a.pkl:1")], score=40, source="deterministic",
    )
    assert f.grounded is True
    assert Finding.model_validate_json(f.model_dump_json()) == f


def test_canonical_json_is_sorted_compact_and_stable():
    assert canonical_json({"b": 1, "a": [2, {"d": 1, "c": 2}]}) == b'{"a":[2,{"c":2,"d":1}],"b":1}'


def test_passport_wire_format_and_id():
    p = mock.signed_passport(mock.MODEL_ID).passport
    doc = json.loads(p.canonical_json())
    assert doc["_type"] == "https://in-toto.io/Statement/v1"
    assert doc["predicateType"] == "https://lineage.dev/passport/v1"
    assert p.passport_id.startswith("lp:") and len(p.passport_id) == 3 + 64
    # round trip through the alias keeps the id
    again = Passport.model_validate(doc)
    assert again.passport_id == p.passport_id


def test_passport_id_ignores_signature_but_tracks_content():
    sp = mock.signed_passport(mock.MODEL_ID)
    resigned = SignedPassport(passport=sp.passport, signature="other", key_id="k2")
    assert resigned.passport_id == sp.passport_id
    changed = sp.passport.model_copy(deep=True)
    changed.predicate.risk_score += 1
    assert changed.passport_id != sp.passport_id


def test_parent_chain_in_mock_uses_real_ids():
    assert mock.signed_passport(mock.MODEL_ID).passport.predicate.parents == [mock.DATASET_ID]


def test_policy_pack_loads_and_versions(policy_path):
    pack = PolicyPack.from_yaml(policy_path)
    assert pack.org == "Apollo Health AI"
    assert pack.environments["prod"].max_risk == 25
    assert pack.thresholds.quarantine == 70
    assert pack.model_files.allow_pickle is False
    assert pack.version == PolicyPack.model_validate(pack.model_dump()).version
    assert PolicyPack.model_validate(__import__("yaml").safe_load(pack.to_yaml())) == pack


def test_decision_roundtrip():
    d = mock.decision("lp:x")
    assert Decision.model_validate_json(d.model_dump_json()) == d
    assert d.decided_at == datetime(2026, 10, 26, 9, 0, tzinfo=timezone.utc)


def test_artifact_detail_validates():
    ArtifactDetail.model_validate(mock.artifact_detail(mock.MODEL_ID).model_dump())
