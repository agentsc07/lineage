"""R1.5 / test 3: a trusted key signs only inside its scope; outside it the passport is treated as unsigned (REFACTOR_SPEC 7.2)."""
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from lineage.intake.pipeline import run_to_decision
from lineage.schemas.passport import Contents, Passport, PassportBody, Signer, SourceRef, Subject, sha256_hex
from lineage.schemas.policy import PolicyPack, TrustedPublisher
from lineage_server import trust
from tests.fakehub import old_release_hub
from tests.server_helpers import KEY, NOW


def passport_for(directory, key, repo, hub="huggingface", action=None, **extra):
    import hashlib

    files = {p.relative_to(directory).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
             for p in sorted(directory.rglob("*")) if p.is_file() and p.name != "passport.json"}
    body = PassportBody(artifact_type="model", name=directory.name, version="1", source=SourceRef(hub=hub, repo=repo),
                        contents=Contents(merkle_root=sha256_hex(repr(sorted(files.items())).encode()), files=files),
                        findings_digest=sha256_hex(b"[]"), risk_score=0, action=action,
                        issued_by=Signer(name="c", key_id=trust.key_id(key.public_key())), issued_at=NOW, **extra)
    signed = trust.sign_passport(Passport(subject=[Subject(name=body.name, digest={"sha256": body.contents.merkle_root})], predicate=body), key)
    (directory / "passport.json").write_text(signed.model_dump_json(by_alias=True))
    return signed


@pytest.fixture
def apollo():
    return Ed25519PrivateKey.generate()


@pytest.fixture
def policy(policy_path, apollo):
    p = PolicyPack.from_yaml(policy_path)
    return p.model_copy(update={"trusted_publishers": [
        TrustedPublisher(name="Apollo ML team", key=trust.public_hex(apollo.public_key()), scope=["upload:*", "hf:apollo-health/*"])]})


def run(model_dir, policy, env="dev"):
    d, _ = run_to_decision("model", str(model_dir), env, policy, "j", now=NOW, hub=old_release_hub())
    return d


def ids(d):
    return {f.id for f in d.findings}


def test_in_scope_passport_gives_signed_trust(policy, apollo, tiny_model):
    passport_for(tiny_model, apollo, "apollo-health/triage")
    d = run(tiny_model, policy)
    assert d.trust_level == "signed" and not {i for i in ids(d) if i.startswith("PROV.SIGNATURE")}


def test_same_passport_claiming_another_publisher_is_a_scope_mismatch(policy, apollo, tiny_model):
    passport_for(tiny_model, apollo, "nvidia/x")
    d = run(tiny_model, policy)
    assert "PROV.SIGNATURE.SCOPE_MISMATCH" in ids(d) and d.trust_level != "signed"


def test_unknown_key_is_treated_as_unsigned(policy, tiny_model):
    passport_for(tiny_model, Ed25519PrivateKey.generate(), "apollo-health/triage")
    d = run(tiny_model, policy)
    assert "PROV.SIGNATURE.UNTRUSTED_KEY" in ids(d) and d.trust_level != "signed"


def test_revoked_key_is_treated_as_unsigned(policy, apollo, tiny_model):
    passport_for(tiny_model, apollo, "apollo-health/triage")
    revoked = policy.model_copy(update={"revoked_keys": [trust.key_id(apollo.public_key())]})
    d = run(tiny_model, revoked)
    assert "PROV.SIGNATURE.REVOKED_KEY" in ids(d) and d.trust_level != "signed"


def test_recorded_needs_inputs_and_sbom_from_lineage_run(policy, apollo, tiny_model):
    from lineage.schemas.passport import Action, SbomComponent

    passport_for(tiny_model, apollo, "apollo-health/triage", action=Action(kind="train"), inputs={"data.csv": "a" * 64},
                 sbom=[SbomComponent(name="torch", version="2.4.1", purl="pkg:pypi/torch@2.4.1")])
    assert run(tiny_model, policy).trust_level == "recorded"


def test_a_signature_that_does_not_verify_is_critical_and_blocks(policy, apollo, tiny_model):
    s = passport_for(tiny_model, apollo, "apollo-health/triage")
    (tiny_model / "passport.json").write_text(s.model_copy(update={"signature": trust.sign_bytes(b"x", apollo)}).model_dump_json(by_alias=True))
    d = run(tiny_model, policy)
    assert "PROV.SIGNATURE.INVALID" in ids(d) and d.outcome == "block"


def test_bootstrap_keys_apply_only_when_the_policy_lists_no_publishers(policy_path, tiny_model, tmp_path):
    """LINEAGE_TRUSTED_KEYS is a dev bootstrap (any scope); a policy with trusted_publishers ignores it."""
    from lineage_server import db
    from lineage_server.registry import SqliteRegistry

    conn = db.connect(tmp_path / "t.db")
    db.init_schema(conn)
    reg = SqliteRegistry(conn, Ed25519PrivateKey.generate())
    trust.trust_key(conn, KEY.public_key(), "trusted-keys-env")
    passport_for(tiny_model, KEY, "nvidia/anything")
    bare = PolicyPack.from_yaml(policy_path)
    d, _ = run_to_decision("model", str(tiny_model), "dev", bare, "j", now=NOW, hub=old_release_hub(), registry=reg)
    assert d.trust_level == "signed"
    other = bare.model_copy(update={"trusted_publishers": [TrustedPublisher(name="x", key="00" * 32, scope=["*"])]})
    d2, _ = run_to_decision("model", str(tiny_model), "dev", other, "j", now=NOW, hub=old_release_hub(), registry=reg)
    assert "PROV.SIGNATURE.UNTRUSTED_KEY" in ids(d2)
