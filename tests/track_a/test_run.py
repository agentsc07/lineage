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
    assert p.trust_level == "unknown"  # trust is decided by the verifier, not by `lineage run` and p.action.kind == "train"
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
