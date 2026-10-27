"""`lineage run -- <cmd>`: record inputs/outputs and emit a child passport (Track A)."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import sysconfig
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path

from lineage.hashing.files import hash_file
from lineage.passport.build import build_passport, contents_for_files
from lineage.schemas.passport import Action, ArtifactType, Passport, SignedPassport, SourceRef, sha256_hex

_SKIP_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__", ".lineage", ".pytest_cache"}

# Injected through PYTHONPATH. Records every file open (the audit hook sees open(), io.open_code,
# os.open ...) to an O_APPEND fd, so child processes append safely. os.write raises no audit event,
# so the hook cannot recurse. A user's own sitecustomize is chained afterwards.
SITECUSTOMIZE = r'''
import os, sys

def _install():
    target = os.environ.get("LINEAGE_RECORD_FILE")
    if not target:
        return
    fd = os.open(target, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    ignore = tuple(p for p in os.environ.get("LINEAGE_IGNORE", "").split(os.pathsep) if p)
    seen = set()
    wmask = os.O_WRONLY | os.O_RDWR | os.O_APPEND | os.O_CREAT | os.O_TRUNC

    def hook(event, args):
        if event != "open":
            return
        path, mode, flags = args
        if isinstance(path, int) or path is None:
            return
        try:
            p = os.path.abspath(os.fsdecode(path))
        except Exception:
            return
        if p.startswith(ignore) or p.endswith(".pyc"):
            return
        write = bool(flags & wmask) if isinstance(flags, int) else False
        if isinstance(mode, str) and any(c in mode for c in "wax+"):
            write = True
        key = (p, write)
        if key in seen:
            return
        seen.add(key)
        os.write(fd, (p + "\t" + ("w" if write else "r") + "\n").encode("utf-8", "surrogateescape"))

    sys.addaudithook(hook)

_install()

# chain to a sitecustomize the user already had
import importlib.machinery, importlib.util
_here = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.machinery.PathFinder.find_spec(
    "sitecustomize", [p for p in sys.path if os.path.abspath(p or ".") != _here]
)
if _spec and _spec.loader:
    _mod = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(_mod)
'''


class CommandFailed(Exception):
    def __init__(self, exit_code: int, command: list[str]):
        super().__init__(f"command exited with status {exit_code}: {' '.join(command)}")
        self.exit_code = exit_code


@dataclass
class RunRecord:
    passport: Passport
    exit_code: int
    inputs: dict[str, str]  # path (workdir-relative when inside, else absolute) -> sha256
    outputs: list[str]
    sbom: str
    duration_s: float
    record_dir: Path
    parents: list[str] = field(default_factory=list)


def _ignore_prefixes() -> list[str]:
    paths = {sys.prefix, sys.base_prefix, sys.exec_prefix, "/dev", "/proc", "/sys", "/usr/lib", "/System", "/Library/Frameworks"}
    paths |= {p for p in sysconfig.get_paths().values() if p}
    return sorted({os.path.realpath(p) for p in paths} | paths)


def _snapshot(root: Path) -> dict[str, tuple[int, int]]:
    snap: dict[str, tuple[int, int]] = {}
    for dirpath, dirs, names in os.walk(root):
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
        for n in names:
            p = Path(dirpath) / n
            try:
                st = p.stat()
            except OSError:
                continue
            snap[p.relative_to(root).as_posix()] = (st.st_size, st.st_mtime_ns)
    return snap


def _freeze(command: list[str]) -> str:
    """`pip freeze` of the interpreter the command uses (falling back to uv, then importlib.metadata)."""
    exe = shutil.which(command[0]) if Path(command[0]).name.startswith("python") else None
    py = exe or sys.executable
    for cmd in ([py, "-m", "pip", "freeze"], ["uv", "pip", "freeze", "--python", py]):
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        except (OSError, subprocess.TimeoutExpired):
            continue
        if r.returncode == 0 and r.stdout.strip():
            return "\n".join(sorted(r.stdout.strip().splitlines())) + "\n"
    from importlib.metadata import distributions

    lines = sorted({f"{d.metadata['Name']}=={d.version}" for d in distributions() if d.metadata["Name"]})
    return "\n".join(lines) + "\n"


def _find_parent_ids(inputs: dict[str, str], workdir: Path) -> list[str]:
    """An input is traced to a parent only if a sibling passport pins that exact file hash."""
    ids: list[str] = []
    for rel, digest in inputs.items():
        f = Path(rel) if os.path.isabs(rel) else workdir / rel
        for cand in (f.with_name(f.name + ".passport.json"), f.parent / "passport.json"):
            if not cand.is_file():
                continue
            try:
                sp = SignedPassport.model_validate_json(cand.read_text())
            except ValueError:
                continue
            files = sp.passport.predicate.contents.files
            if digest in (files.get(f.name), files.get(rel)) and sp.passport_id not in ids:
                ids.append(sp.passport_id)
    return ids


def run_recorded_full(
    command: list[str],
    workdir: Path,
    parents: list[str] | None = None,
    *,
    name: str | None = None,
    version: str = "0.0.0",
    artifact_type: ArtifactType = "model",
    kind: str = "train",
) -> RunRecord:
    """Run `command` with an audit-hook sitecustomize injected via PYTHONPATH, capture files opened,
    `pip freeze` as SBOM and outputs; return a RunRecord whose passport is (trust is decided by the verifier, not the signer)."""
    if not command:
        raise ValueError("no command given")
    workdir = Path(workdir).resolve()
    run_id = time.strftime("%Y%m%dT%H%M%S") + f"-{os.getpid()}"
    record_dir = workdir / ".lineage" / "runs" / run_id
    record_dir.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="lineage_hook_") as hook_dir:
        (Path(hook_dir) / "sitecustomize.py").write_text(SITECUSTOMIZE)
        log = Path(hook_dir) / "opens.log"
        env = dict(os.environ)
        env["PYTHONPATH"] = os.pathsep.join(filter(None, [hook_dir, env.get("PYTHONPATH")]))
        env["LINEAGE_RECORD_FILE"] = str(log)
        env["LINEAGE_IGNORE"] = os.pathsep.join(_ignore_prefixes() + [hook_dir, str(workdir / ".lineage")])
        before = _snapshot(workdir)
        t0 = time.monotonic()
        exit_code = subprocess.run(command, cwd=workdir, env=env).returncode
        duration = time.monotonic() - t0
        after = _snapshot(workdir)
        opened = log.read_text(errors="surrogateescape").splitlines() if log.exists() else []

    read: set[Path] = set()
    written: set[Path] = set()
    for line in opened:
        p, _, mode = line.rpartition("\t")
        (written if mode == "w" else read).add(Path(p))

    def rel(p: Path) -> str:
        try:
            return p.relative_to(workdir).as_posix()
        except ValueError:
            return str(p)

    changed = {r for r, sig in after.items() if before.get(r) != sig}
    out_rels = sorted(
        {rel(p) for p in written if p.is_file() and p.is_relative_to(workdir)} | changed
    )
    out_rels = [r for r in out_rels if not (set(Path(r).parts) & _SKIP_DIRS) and (workdir / r).is_file()]
    in_paths = sorted(
        p for p in read - written if p.is_file() and rel(p) not in out_rels and not (set(p.parts) & {"__pycache__"})
    )
    with ThreadPoolExecutor(max_workers=8) as pool:
        in_hashes = dict(zip((rel(p) for p in in_paths), pool.map(hash_file, in_paths)))

    sbom = _freeze(command)
    (record_dir / "sbom.txt").write_text(sbom)
    all_parents = list(dict.fromkeys([*(parents or []), *_find_parent_ids(in_hashes, workdir)]))
    run_name = name or f"{workdir.name}-run"
    passport = build_passport(
        workdir,
        artifact_type,
        run_name,
        version,
        SourceRef(hub="local-run"),
        parents=all_parents,
        action=Action(kind=kind, command=list(command), env_sbom_digest=sha256_hex(sbom.encode())),  # type: ignore[arg-type]
        contents=contents_for_files(workdir, out_rels),
    )
    (record_dir / "run.json").write_text(
        json.dumps(
            {"command": command, "exit_code": exit_code, "duration_s": round(duration, 3),
             "inputs": in_hashes, "outputs": out_rels, "passport_id": passport.passport_id},
            indent=2,
        )
    )
    return RunRecord(passport, exit_code, in_hashes, out_rels, sbom, duration, record_dir, all_parents)


def run_recorded(command: list[str], workdir: Path, parents: list[str] | None = None) -> Passport:
    """Run `command` recorded; return the child passport. Raises CommandFailed on a non-zero exit."""
    rec = run_recorded_full(command, workdir, parents)
    if rec.exit_code != 0:
        raise CommandFailed(rec.exit_code, command)
    return rec.passport
