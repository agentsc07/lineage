"""Build a passport from an artifact on disk (Track A)."""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from lineage.hashing.files import hash_file, hash_tree
from lineage.hashing.merkle import merkle_root
from lineage.hashing.tensors import hash_gguf, hash_safetensors
from lineage.schemas.finding import Finding
from lineage.schemas.passport import (
    Action,
    ArtifactType,
    Contents,
    Passport,
    PassportBody,
    Signer,
    SourceRef,
    Subject,
    TrustLevel,
    canonical_json,
    sha256_hex,
)


def _tensor_hashes(root: Path, files: dict[str, str]) -> dict[str, str] | None:
    """Per-tensor hashes for every safetensors/GGUF file. Bare tensor names when there is one such file,
    otherwise `<file>::<name>` so shards never collide. None if the artifact has no tensor files."""
    tensor_files = sorted(f for f in files if f.endswith((".safetensors", ".gguf")))
    if not tensor_files:
        return None
    out: dict[str, str] = {}
    for rel in tensor_files:
        p = root / rel if root.is_dir() else root
        hashes = hash_safetensors(p) if rel.endswith(".safetensors") else hash_gguf(p)
        prefix = "" if len(tensor_files) == 1 else f"{rel}::"
        out.update({prefix + k: v for k, v in hashes.items()})
    return out


def contents_for_files(root: Path, rels: list[str]) -> Contents:
    """Like `hash_contents` but for an explicit set of files under `root` (e.g. a run's outputs)."""
    root = Path(root)
    files = {rel: hash_file(root / rel) for rel in sorted(rels)}
    return _assemble(root, files)


def _assemble(root: Path, files: dict[str, str]) -> Contents:
    tensors = _tensor_hashes(root, files)
    leaves = {f"file:{k}": v for k, v in files.items()}
    leaves |= {f"tensor:{k}": v for k, v in (tensors or {}).items()}
    return Contents(merkle_root=merkle_root(leaves), files=files, tensors=tensors)


def hash_contents(path: Path) -> Contents:
    """Hash files (and tensors for models). The Merkle leaves are `file:<path>` and `tensor:<name>`.

    Shared by build, verify and `lineage.load` so all three agree on what 'the same bytes' means.
    """
    path = Path(path)
    return _assemble(path, hash_tree(path))


def findings_digest(findings: list[Finding]) -> str:
    return sha256_hex(canonical_json([f.model_dump(mode="json") for f in findings]))


def build_passport(
    path: Path,
    artifact_type: ArtifactType,
    name: str,
    version: str,
    source: SourceRef,
    *,
    parents: list[str] | None = None,
    action: Action | None = None,
    trust_level: TrustLevel = "unknown",
    findings: list[Finding] | None = None,
    signer_name: str = "local",
    contents: Contents | None = None,
) -> Passport:
    """Hash `path` (files, and tensors for models), compute the Merkle root and assemble the statement."""
    findings = findings or []
    contents = contents or hash_contents(path)
    body = PassportBody(
        artifact_type=artifact_type,
        name=name,
        version=version,
        source=source,
        contents=contents,
        parents=list(parents or []),
        action=action,
        trust_level=trust_level,
        findings_digest=findings_digest(findings),
        risk_score=min(100, sum(f.score for f in findings)),
        issued_by=Signer(name=signer_name),
        issued_at=datetime.now(timezone.utc).replace(microsecond=0),
    )
    return Passport(subject=[Subject(name=name, digest={"sha256": contents.merkle_root})], predicate=body)
