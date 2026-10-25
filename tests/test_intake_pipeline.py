import json
import shutil
from datetime import timedelta

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from lineage.intake import gpu, inspectors as insp
from lineage.intake.pipeline import run_intake, run_to_decision
from lineage.policy.engine import decide
from lineage.schemas.gpu import (
    BehaviourDiffResponse, Claim, NotaryCheckResponse, ParentResponse, ReviewResponse, SpectralResponse,
)
from lineage.schemas.policy import PolicyPack
from lineage_server import db, models, service, trust
from lineage_server.registry import SqliteRegistry
from mcp_gateway.gateway import pins_from_db
from tests.server_helpers import KEY, NOW, finding, make_signed, ship_passport


@pytest.fixture
def policy(policy_path):
    return PolicyPack.from_yaml(policy_path)


@pytest.fixture
def conn(tmp_path):
    c = db.connect(tmp_path / "t.db")
    db.init_schema(c)
    return c


@pytest.fixture
def registry(conn):
    reg = SqliteRegistry(conn, Ed25519PrivateKey.generate())
    trust.trust_key(conn, KEY.public_key(), "creator")  # artifacts shipped with KEY-signed passports are verifiable
    return reg


def intake(kind, ref, env="dev", policy=None, **kw):
    kw.setdefault("now", NOW)
    return run_to_decision(kind, str(ref), env, policy, "job1", **kw)


def ids(decision):
    return {f.id for f in decision.findings}


# --- shape of the event stream ---
def test_event_stream_shape_and_decision_on_s6(policy, tiny_dataset):
    decision, events = intake("dataset", tiny_dataset, policy=policy)
    assert [(e.stage, e.status) for e in events][:2] == [("S1", "started"), ("S1", "completed")]
    assert [e.stage for e in events if e.status != "started"] == ["S1", "S2", "S3", "S4", "S5", "S6", "S7"]
    with_decision = [e for e in events if e.decision]
    assert len(with_decision) == 1 and with_decision[0].stage == "S6" and with_decision[0].decision == decision
    assert {e.job_id for e in events} == {"job1"}


def test_clean_dev_dataset_skips_deep_stages_and_is_allowed(policy, tiny_dataset):
    decision, events = intake("dataset", tiny_dataset, policy=policy)
    by_stage = {e.stage: e for e in events if e.status != "started"}
    assert by_stage["S4"].status == "skipped" and by_stage["S5"].status == "skipped"
    assert decision.outcome == "allow" and decision.trust_level == "inspected"
    assert any(i.startswith("SCANNER.UNAVAILABLE") for i in ids(decision))  # Track C stubs degrade to info


def test_unknown_environment_raises_before_any_event(policy, tiny_dataset):
    with pytest.raises(ValueError, match="unknown environment"):
        list(run_intake("dataset", str(tiny_dataset), "qa", policy, "j"))


def test_persisted_through_sqlite_registry_and_duplicate_digest_noted(policy, tiny_dataset, conn, registry):
    d1, events = intake("dataset", tiny_dataset, policy=policy, registry=registry)
    assert events[-1].status == "completed" and d1.artifact_id in events[-1].message
    art = models.get_artifact(conn, d1.artifact_id)
    assert art.artifact.status == "admitted" and art.decision == d1 and art.passport.passport_id == d1.artifact_id
    assert trust.verify_signed(art.passport, registry.key.public_key())  # org-signed
    d2, _ = intake("dataset", tiny_dataset, policy=policy, registry=registry, now=NOW + timedelta(seconds=5))
    assert "INTAKE.DIGEST.KNOWN" in ids(d2) and d2.artifact_id != d1.artifact_id


# --- signed passports shipped with artifacts ---
@pytest.fixture
def model_dir(tmp_path, tiny_model):
    return tiny_model


def test_valid_shipped_passport_checks_out(policy, model_dir, registry):
    ship_passport(model_dir)
    d, _ = intake("model", model_dir, policy=policy, registry=registry)
    assert d.outcome == "allow" and not any(i.startswith(("PROV.SIGNATURE", "INTEGRITY")) for i in ids(d))


def test_tampered_file_after_signing_is_a_hash_mismatch_block(policy, model_dir, registry):
    ship_passport(model_dir)
    (model_dir / "config.json").write_text(json.dumps({"model_type": "tiny", "trust_remote_code": True}))
    d, _ = intake("model", model_dir, policy=policy, registry=registry)
    assert d.outcome == "block" and "INTEGRITY.HASH_MISMATCH" in ids(d)
    assert any("hash mismatch" in r for r in d.reasons)


def test_swapped_tokenizer_after_approval_style_added_file(policy, model_dir, registry):
    ship_passport(model_dir)
    (model_dir / "tokenizer.json").write_text("{}")
    d, _ = intake("model", model_dir, policy=policy, registry=registry)
    assert "INTEGRITY.UNPINNED_FILE" in ids(d)


def test_invalid_signature_blocks(policy, model_dir, registry):
    ship_passport(model_dir, tamper_signature=True)
    d, _ = intake("model", model_dir, policy=policy, registry=registry)
    assert d.outcome == "block" and "PROV.SIGNATURE.INVALID" in ids(d)


def test_untrusted_signer_is_a_finding_not_a_block(policy, model_dir, registry):
    ship_passport(model_dir, key=Ed25519PrivateKey.generate())
    d, _ = intake("model", model_dir, policy=policy, registry=registry)
    assert "PROV.SIGNATURE.UNTRUSTED_KEY" in ids(d) and d.outcome != "block"


def test_chain_to_admitted_parent_allows_but_revoked_parent_blocks(policy, model_dir, registry, conn):
    parent = make_signed("radiology-notes", "dataset")
    pid = parent.passport_id
    service.record(conn, parent, [], decide(parent.passport.predicate, [], "dev", policy, NOW, artifact_id=pid))
    ship_passport(model_dir, parents=[pid])
    d, _ = intake("model", model_dir, policy=policy, registry=registry)
    assert d.outcome == "allow"
    assert conn.execute("SELECT child FROM edges WHERE parent = ?", (pid,)).fetchone()["child"] == d.artifact_id
    service.revoke(conn, pid, "poisoned", policy, now=NOW)
    d2, _ = intake("model", model_dir, policy=policy, registry=registry, now=NOW + timedelta(seconds=9))
    assert d2.outcome == "block" and "PROV.PARENT.REVOKED" in ids(d2)
    assert models.artifact_row(conn, d.artifact_id).status == "blocked"  # the earlier child was flagged by the revoke


def test_unknown_parent_is_flagged(policy, model_dir, registry):
    ship_passport(model_dir, parents=["lp:" + "a" * 64])
    d, _ = intake("model", model_dir, policy=policy, registry=registry)
    assert "PROV.PARENT.UNKNOWN" in ids(d)


# --- hard blocks from content ---
def test_pickle_weights_block(policy, tmp_path):
    d = tmp_path / "m"
    d.mkdir()
    (d / "pytorch_model.bin").write_bytes(b"\x80\x04N.")
    dec, _ = intake("model", d, policy=policy)
    assert dec.outcome == "block" and any("pickle" in r for r in dec.reasons)


def test_blocked_publisher_via_metadata_repo(policy, tmp_path):
    d = tmp_path / "m"
    d.mkdir()
    (d / "model.safetensors").write_bytes(b"x")
    (d / "lineage.meta.json").write_text(json.dumps({"repo": "someone/llama-official-mirror"}))
    dec, _ = intake("model", d, policy=policy)
    assert dec.outcome == "block" and "PROV.PUBLISHER.BLOCKED" in ids(dec)


def test_lookalike_publisher_detected(policy, tmp_path):
    d = tmp_path / "m"
    d.mkdir()
    (d / "model.safetensors").write_bytes(b"x")
    (d / "lineage.meta.json").write_text(json.dumps({"repo": "meta-liama/Llama-3.2-1B"}))
    assert "PROV.LOOKALIKE.PUBLISHER" in ids(intake("model", d, policy=policy)[0])


# --- remote refs, missing paths ---
def test_remote_reference_is_unknown_trust_and_quarantined_in_dev(policy):
    d, _ = intake("model", "meta-llama/Llama-3.2-1B", policy=policy)
    assert d.trust_level == "unknown" and "PROV.UNVERIFIED.REMOTE_REF" in ids(d)
    assert d.outcome == "quarantine" and any("below dev minimum" in r for r in d.reasons)


@pytest.mark.parametrize("ref", ["./definitely/not/here", "/definitely/not/here"])
def test_missing_local_path_fails_s1_but_still_decides(policy, ref):
    d, events = run_to_decision("model", ref, "dev", policy, "j", now=NOW)
    assert next(e for e in events if e.stage == "S1" and e.status != "started").status == "failed"
    assert "INTAKE.REF.NOT_FOUND" in ids(d) and d.outcome == "quarantine"


# --- packages / cooldown ---
def test_young_package_release_is_quarantined_by_cooldown(policy, tmp_path):
    p = tmp_path / "litellm"
    shutil.copytree("tests/fixtures/toy_package", p)
    (p / "lineage.meta.json").write_text(json.dumps({"released_at": (NOW - timedelta(hours=2)).isoformat()}))
    d, _ = intake("package", p, policy=policy)
    assert d.outcome == "quarantine" and any(r.startswith("cooldown") for r in d.reasons)


def test_explicit_metadata_overrides_sidecar_and_pypi_style_upload_time(policy, tmp_path):
    p = tmp_path / "pkg"
    shutil.copytree("tests/fixtures/toy_package", p)
    meta = {"urls": [{"upload_time_iso_8601": (NOW - timedelta(days=30)).isoformat()}]}
    d, _ = intake("package", p, policy=policy, metadata=meta)
    assert d.outcome == "allow"


# --- tools / agents ---
def test_tool_is_quarantined_for_human_and_pins_are_recorded(policy, toy_tool, tmp_path, conn, registry):
    t = tmp_path / "word_count"
    shutil.copytree(toy_tool, t)
    d, _ = intake("tool", t, policy=policy, registry=registry)
    assert d.outcome == "quarantine" and "human approval required by policy" in d.reasons
    assert pins_from_db(conn) == {}  # not admitted yet, so not pinned
    from lineage.schemas.artifact import ApprovalRequest

    service.approve(conn, d.artifact_id, ApprovalRequest(approver="dr.rao", reason="ok", expires=NOW + timedelta(days=3)), policy, now=NOW)
    pins = pins_from_db(conn)
    assert set(pins) == {"word_count"} and set(pins["word_count"]) == {"description_sha256", "code_sha256"}


def test_agent_with_revoked_part_is_blocked(policy, tmp_path, conn, registry):
    part = make_signed("triage-llama-ft", "model")
    service.record(conn, part, [], decide(part.passport.predicate, [], "dev", policy, NOW, artifact_id=part.passport_id))
    a = tmp_path / "agent"
    a.mkdir()
    (a / "agent.json").write_text(json.dumps({"name": "triage-agent", "version": "0.3.0", "parts": [part.passport_id]}))
    ok, _ = intake("agent", a, policy=policy, registry=registry)
    assert ok.outcome == "allow" and conn.execute("SELECT parent FROM edges").fetchone()["parent"] == part.passport_id
    service.revoke(conn, part.passport_id, "recalled", policy, now=NOW)
    bad, _ = intake("agent", a, policy=policy, registry=registry, now=NOW + timedelta(seconds=3))
    assert bad.outcome == "block" and "PROV.PARENT.REVOKED" in ids(bad)


# --- scanners, registry and failures ---
def test_registered_scanner_runs_and_gates_deep_stages(policy, tiny_dataset, monkeypatch):
    monkeypatch.setitem(insp.INSPECTORS, ("dataset", "S3"), [("probe", lambda ctx: [finding("DATA.PROBE", "medium", 12, category="data")])])
    monkeypatch.setitem(insp.INSPECTORS, ("dataset", "S5"), [("deep", lambda ctx: [finding("LLM.DEEP", "low", 5, category="llm", stage="S5")])])
    d, events = intake("dataset", tiny_dataset, policy=policy)
    s5 = next(e for e in events if e.stage == "S5" and e.status != "started")
    assert s5.status == "completed" and "LLM.DEEP" in ids(d)  # medium finding at S3 raised suspicion


def test_crashing_scanner_becomes_medium_finding_not_a_crash(policy, tiny_dataset, monkeypatch):
    def boom(ctx):
        raise RuntimeError("parser exploded")

    monkeypatch.setitem(insp.INSPECTORS, ("dataset", "S3"), [("boom", boom)])
    d, events = intake("dataset", tiny_dataset, policy=policy)
    f = next(f for f in d.findings if f.id == "SCANNER.ERROR.BOOM")
    assert f.severity == "medium" and "parser exploded" in f.title
    assert events[-1].stage == "S7"


def test_stage_level_failure_is_reported_and_pipeline_continues(policy, tiny_dataset, monkeypatch):
    real = insp.inspectors_for

    def flaky(kind, stage):
        if stage == "S3":
            raise OSError("disk gone")
        return real(kind, stage)

    monkeypatch.setattr(insp, "inspectors_for", flaky)
    d, events = intake("dataset", tiny_dataset, policy=policy)
    s3 = next(e for e in events if e.stage == "S3" and e.status != "started")
    assert s3.status == "failed" and "disk gone" in s3.message and "INTAKE.STAGE.ERROR" in ids(d)
    assert events[-1].stage == "S7"


def test_registry_failure_at_s7_is_reported_not_raised(policy, tiny_dataset):
    class Broken:
        def __getattr__(self, name):
            from lineage.intake.registry import NullRegistry

            if name == "record":
                def record(*a, **k):
                    raise RuntimeError("db locked")
                return record
            return getattr(NullRegistry(), name)

    d, events = intake("dataset", tiny_dataset, policy=policy, registry=Broken())
    assert events[-1].status == "failed" and "db locked" in events[-1].message and d.outcome == "allow"


# --- GPU stages ---
def fake_gpu(monkeypatch, spectral=0.93, divergence=0.42, parent="meta-llama/Llama-3.2-1B", claims=None, notary_match=True):
    def post(path, request, response_model, base_url=None, timeout=0):
        if path == "/weights/parent":
            return ParentResponse(parent=parent, similarity=0.97, changed_layers=[f"layers.{i}.weight" for i in range(28, 33)])
        if path == "/weights/spectral":
            return SpectralResponse(score=spectral, per_layer={"layers.30.weight": {"kurtosis": 41.0, "energy": 0.9}})
        if path == "/behaviour/diff":
            return BehaviourDiffResponse(divergence=divergence, flagged_probes=[{"id": "p7", "prompt": "..."}])
        if path == "/notary/check":
            return NotaryCheckResponse(cert_id=request.cert_id, match=notary_match, detail="fingerprint differs")
        if path == "/review/card":
            return ReviewResponse(claims=claims or [], verdict="suspicious")
        raise AssertionError(path)

    monkeypatch.setattr(gpu, "post", post)


def test_model_deep_inspection_flags_backdoor_signals(policy, model_dir, monkeypatch):
    fake_gpu(monkeypatch)
    (model_dir / "lineage.meta.json").write_text(json.dumps({"claimed_base": "Qwen/Qwen2.5-1.5B"}))
    d, events = intake("model", model_dir, env="staging", policy=policy)
    got = ids(d)
    assert {"MODEL.WEIGHTS.CHANGED_LAYERS", "MODEL.WEIGHTS.SPECTRAL_ANOMALY", "MODEL.BEHAVIOUR.DIVERGENCE",
            "MODEL.PARENT.CLAIM_MISMATCH"} <= got
    spectral = next(f for f in d.findings if f.id == "MODEL.WEIGHTS.SPECTRAL_ANOMALY")
    assert spectral.severity == "high" and spectral.source == "statistical" and spectral.evidence[0].kind == "tensor"
    assert d.outcome in ("quarantine", "block")


def test_gpu_unreachable_degrades_to_info_finding(policy, model_dir):
    d, events = intake("model", model_dir, env="staging", policy=policy, gpu_url="http://127.0.0.1:9")  # closed port
    skipped = [f for f in d.findings if f.id == "GPU.CHECK.SKIPPED"]
    assert skipped and all(f.severity == "info" and f.score == 0 for f in skipped)
    assert events[-1].stage == "S7" and next(e for e in events if e.stage == "S4" and e.status != "started").status == "completed"


def test_card_review_claims_are_grounded_and_ungrounded_ones_dropped(policy, model_dir, monkeypatch):
    (model_dir / "README.md").write_text("# card\nSafe model.\nIt runs eval(payload) at load.\n")
    claims = [
        Claim(text="card hides eval", file="README.md", line=3, api="eval(", severity="high"),
        Claim(text="invented exec", file="README.md", line=2, api="subprocess", severity="critical"),
    ]
    fake_gpu(monkeypatch, parent=None, claims=claims)
    d, _ = intake("model", model_dir, env="staging", policy=policy)
    grounded = [f for f in d.findings if f.id == "LLM.CARD.CLAIM"]
    assert len(grounded) == 1 and grounded[0].evidence[0].ref == "README.md:3" and grounded[0].grounded
    dropped = next(f for f in d.findings if f.id == "LLM.CARD.UNGROUNDED")
    assert dropped.score == 0 and not dropped.grounded
    assert d.risk_score >= 25


def test_notary_mismatch_flagged(policy, model_dir, monkeypatch, registry):
    import hashlib

    from lineage.schemas.passport import Contents, Passport, PassportBody, SourceRef, Subject, Signer, sha256_hex

    files = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in model_dir.iterdir() if p.is_file()}
    body = PassportBody(artifact_type="model", name="m", version="1", source=SourceRef(), contents=Contents(merkle_root="0" * 64, files=files),
                        trust_level="declared", findings_digest=sha256_hex(b"[]"), risk_score=0, certificates=["cert-1"],
                        issued_by=Signer(name="c"), issued_at=NOW)
    sp = trust.sign_passport(Passport(subject=[Subject(name="m", digest={"sha256": "0" * 64})], predicate=body), KEY)
    (model_dir / "passport.json").write_text(sp.model_dump_json(by_alias=True))
    fake_gpu(monkeypatch, spectral=0.1, divergence=0.0, notary_match=False)
    d, _ = intake("model", model_dir, env="staging", policy=policy, registry=registry)
    assert "MODEL.NOTARY.MISMATCH" in ids(d)
