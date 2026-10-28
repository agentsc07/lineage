import hashlib
import json
import sys
import textwrap

import pytest

from lineage.passport.build import build_passport
from lineage.run import CommandFailed, run_recorded, run_recorded_full
from lineage.schemas.passport import SourceRef
from lineage.signing.ed25519 import sign_passport
from lineage.signing.keys import generate_keypair, load_private_key


@pytest.fixture
def project(tmp_path, tiny_dataset):
    w = tmp_path / "proj"
    w.mkdir()
    (w / "data.csv").write_bytes(tiny_dataset.read_bytes())
    (w / "train.py").write_text(textwrap.dedent("""
        rows = open("data.csv").read().splitlines()
        open("out.txt", "w").write(str(len(rows)))
    """))
    return w


def test_records_inputs_outputs_and_emits_recorded_passport(project):
    rec = run_recorded_full([sys.executable, "train.py"], project)
    p = rec.passport.predicate
    assert p.trust_level == "unknown" and p.action.kind == "train"  # trust is decided by the verifier, not by `lineage run`
    assert p.action.command == [sys.executable, "train.py"]
    assert set(p.contents.files) == {"out.txt"}
    assert p.contents.files["out.txt"] == hashlib.sha256(b"21").hexdigest()
    assert rec.inputs["data.csv"] == hashlib.sha256((project / "data.csv").read_bytes()).hexdigest()
    assert "train.py" in rec.inputs  # code is an input too
    assert "out.txt" not in rec.inputs
    assert not any("site-packages" in k or "lib/python" in k for k in rec.inputs)
    assert p.action.env_sbom_digest and len(p.action.env_sbom_digest) == 64


def test_sbom_and_run_record_written(project):
    rec = run_recorded_full([sys.executable, "train.py"], project)
    assert rec.record_dir.is_dir()
    sbom = (rec.record_dir / "sbom.txt").read_text()
    assert "pydantic" in sbom.lower()
    assert hashlib.sha256(sbom.encode()).hexdigest() == rec.passport.predicate.action.env_sbom_digest
    data = json.loads((rec.record_dir / "run.json").read_text())
    assert data["exit_code"] == 0 and data["outputs"] == ["out.txt"]


def test_subprocess_children_are_recorded(project):
    (project / "parent.py").write_text(textwrap.dedent(f"""
        import subprocess, sys
        subprocess.run([sys.executable, "-c", "open('child_out.txt','w').write(open('data.csv').read()[:3])"], check=True)
    """))
    rec = run_recorded_full([sys.executable, "parent.py"], project)
    assert "child_out.txt" in rec.passport.predicate.contents.files and "data.csv" in rec.inputs


def test_non_python_command_outputs_found_by_snapshot(project):
    rec = run_recorded_full(["sh", "-c", "echo hi > shell_out.txt"], project)
    assert set(rec.passport.predicate.contents.files) == {"shell_out.txt"}


def test_input_with_passport_becomes_parent(project, tmp_path):
    generate_keypair(tmp_path / "k")
    ds = build_passport(project / "data.csv", "dataset", "d", "1", SourceRef())
    signed = sign_passport(ds, load_private_key(tmp_path / "k" / "default.key"), "k")
    (project / "data.csv.passport.json").write_text(signed.model_dump_json(by_alias=True))
    p = run_recorded([sys.executable, "train.py"], project)
    assert p.predicate.parents == [ds.passport_id]


def test_stale_passport_is_not_a_parent(project, tmp_path):
    generate_keypair(tmp_path / "k")
    ds = build_passport(project / "data.csv", "dataset", "d", "1", SourceRef())
    signed = sign_passport(ds, load_private_key(tmp_path / "k" / "default.key"), "k")
    (project / "data.csv.passport.json").write_text(signed.model_dump_json(by_alias=True))
    (project / "data.csv").write_text("tampered\n")
    assert run_recorded([sys.executable, "train.py"], project).predicate.parents == []


def test_explicit_parents_kept(project):
    p = run_recorded([sys.executable, "train.py"], project, parents=["lp:abc"])
    assert "lp:abc" in p.predicate.parents


def test_failing_command_raises_with_exit_code(project):
    with pytest.raises(CommandFailed) as e:
        run_recorded([sys.executable, "-c", "import sys; sys.exit(3)"], project)
    assert e.value.exit_code == 3


def test_empty_command_rejected(project):
    with pytest.raises(ValueError):
        run_recorded([], project)


def test_user_sitecustomize_still_runs(project, tmp_path):
    other = tmp_path / "other"
    other.mkdir()
    (other / "sitecustomize.py").write_text("import builtins; builtins.USER_SC = 1\n")
    import os
    old = os.environ.get("PYTHONPATH")
    os.environ["PYTHONPATH"] = str(other)
    try:
        rec = run_recorded_full(
            [sys.executable, "-c", "import builtins; open('flag.txt','w').write(str(getattr(builtins,'USER_SC',0)))"],
            project,
        )
    finally:
        os.environ.pop("PYTHONPATH") if old is None else os.environ.__setitem__("PYTHONPATH", old)
    assert (project / "flag.txt").read_text() == "1" and "flag.txt" in rec.passport.predicate.contents.files


def test_passport_v2_carries_inputs_and_sbom(project):
    p = run_recorded_full([sys.executable, "train.py"], project).passport.predicate
    assert p.inputs["data.csv"] == hashlib.sha256((project / "data.csv").read_bytes()).hexdigest() and "out.txt" not in p.inputs
    assert any(c.name.lower() == "pydantic" and c.purl.startswith("pkg:pypi/pydantic@") for c in p.sbom)


def test_cli_run_writes_the_passport_beside_each_output(project, monkeypatch):
    from typer.testing import CliRunner

    from lineage.cli import app

    monkeypatch.chdir(project)
    d = project / "keys"
    generate_keypair(d)
    r = CliRunner().invoke(app, ["run", "--key", str(d / "default.key"), "--fact", "licence=mit", "--", sys.executable, "train.py"])
    assert r.exit_code == 0, r.output
    doc = json.loads((project / "out.txt.passport.json").read_text())
    body = doc["passport"]["predicate"]
    assert body["action"]["kind"] == "train" and body["inputs"] and body["sbom"] and body["facts"][0]["key"] == "licence" and doc["signature"]


def test_input_pulled_from_the_registry_becomes_a_parent(project, tmp_path):
    """`lineage pull` leaves `<folder>.lineage-attestation.json` beside the folder; a run that reads those exact bytes names that artifact as a parent."""
    from datetime import datetime, timedelta, timezone

    from lineage.client import cache_path
    from lineage.schemas.attestation import Attestation, SignedAttestation

    pulled = project / "admitted" / "triage-base"
    pulled.mkdir(parents=True)
    (pulled / "weights.bin").write_bytes(b"admitted bytes")
    now = datetime.now(timezone.utc)
    att = Attestation(artifact_id="lp:" + "ab" * 32, digest="d", files={"weights.bin": hashlib.sha256(b"admitted bytes").hexdigest()}, outcome="allow",
                      environment="dev", trust="origin_verified", policy_version="pp:x", issued_at=now, expires_at=now + timedelta(days=1))
    cache_path(pulled).write_text(SignedAttestation(attestation=att, signature="", key_id="k").model_dump_json())
    (project / "train.py").write_text("open('admitted/triage-base/weights.bin','rb').read(); open('out.txt','w').write('x')\n")
    assert run_recorded([sys.executable, "train.py"], project).predicate.parents == [att.artifact_id]
    (pulled / "weights.bin").write_bytes(b"edited after the pull")
    assert run_recorded([sys.executable, "train.py"], project).predicate.parents == []


def test_a_verified_load_inside_a_run_names_its_parent_even_when_the_weights_are_read_natively(project, tmp_path):
    """safetensors reads weights without a Python `open`, so the file hook misses them; `lineage.load()` reports the artifact it verified."""
    from datetime import datetime, timedelta, timezone

    from lineage.client import cache_path
    from lineage.hashing.files import hash_tree
    from lineage.schemas.attestation import Attestation, SignedAttestation

    pulled = project / "admitted" / "m"
    pulled.mkdir(parents=True)
    from safetensors.numpy import save_file
    import numpy as np

    save_file({"w": np.ones((2, 2), np.float32)}, str(pulled / "model.safetensors"))
    now = datetime.now(timezone.utc)
    att = Attestation(artifact_id="lp:" + "cd" * 32, digest="d", files=hash_tree(pulled), outcome="allow", environment="dev", trust="origin_verified",
                      policy_version="pp:x", issued_at=now, expires_at=now + timedelta(days=1))
    cache_path(pulled).write_text(SignedAttestation(attestation=att, signature="", key_id="k").model_dump_json())
    (project / "train.py").write_text(textwrap.dedent("""
        from lineage import client
        from safetensors.numpy import load_file
        from pathlib import Path
        from lineage.signing.keys import generate_keypair
        # what load() does after its checks pass, without needing a registry in this test
        client.note_use("%s")
        load_file("admitted/m/model.safetensors")
        open("out.txt", "w").write("x")
    """ % att.artifact_id))
    rec = run_recorded_full([sys.executable, "train.py"], project)
    assert rec.passport.predicate.parents == [att.artifact_id] and "admitted/m/model.safetensors" not in rec.inputs


def test_packages_installed_into_a_pythonpath_folder_are_in_the_package_list(project, tmp_path, monkeypatch):
    libs = tmp_path / "libs"
    (libs / "acme_llm-1.4.0.dist-info").mkdir(parents=True)
    (libs / "acme_llm-1.4.0.dist-info" / "METADATA").write_text("Metadata-Version: 2.1\nName: acme-llm\nVersion: 1.4.0\n")
    monkeypatch.setenv("PYTHONPATH", str(libs))
    rec = run_recorded_full([sys.executable, "train.py"], project)
    assert "acme-llm==1.4.0" in rec.sbom.splitlines()


def test_lineage_own_config_and_attestations_are_not_recorded_as_inputs(project, tmp_path, monkeypatch):
    cfg = tmp_path / "lineage-config.toml"
    cfg.write_text('registry_pubkey = "ab"\n')
    monkeypatch.setenv("LINEAGE_CONFIG", str(cfg))
    (project / "m.lineage-attestation.json").write_text("{}")
    (project / "train.py").write_text(f"open({str(cfg)!r}).read(); open('m.lineage-attestation.json').read(); open('data.csv').read(); open('out.txt', 'w').write('x')\n")
    rec = run_recorded_full([sys.executable, "train.py"], project)
    assert set(rec.inputs) == {"data.csv", "train.py"}
