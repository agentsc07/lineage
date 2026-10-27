"""Content-addressed store (REFACTOR_SPEC 3.5, P4): the exact bytes Lineage admitted, and the only place code fetches them from.

    <root>/blobs/sha256/<aa>/<hash>        one blob per distinct file
    <root>/manifests/<artifact_id>.json    {artifact_id, files: {path: sha256}, distribution?: {filename, sha256}}

Intake writes every file of every artifact it receives (uploads and fetches) before inspecting it. Bytes are never served
unless the latest attestation for the requested environment allows them; that check lives in the server, not here.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
from pathlib import Path


def default_root() -> Path:
    return Path(os.environ.get("LINEAGE_STORE", "lineage-store"))


class Store:
    def __init__(self, root: Path | str | None = None):
        self.root = Path(root) if root else default_root()

    def blob_path(self, sha256: str) -> Path:
        return self.root / "blobs" / "sha256" / sha256[:2] / sha256

    def has(self, sha256: str) -> bool:
        return self.blob_path(sha256).is_file()

    def put_file(self, path: Path, sha256: str | None = None) -> str:
        """Copy `path` into the store under its sha256 (computed here unless the caller already has it). Idempotent."""
        if sha256 is None:
            h = hashlib.sha256()
            with path.open("rb") as f:
                for chunk in iter(lambda: f.read(8 * 1024 * 1024), b""):
                    h.update(chunk)
            sha256 = h.hexdigest()
        dest = self.blob_path(sha256)
        if not dest.exists():
            dest.parent.mkdir(parents=True, exist_ok=True)
            tmp = dest.with_name(dest.name + f".tmp{os.getpid()}")
            shutil.copyfile(path, tmp)
            os.replace(tmp, dest)
        return sha256

    def put_tree(self, root: Path, files: dict[str, str]) -> None:
        """Store every file of an artifact; `files` is path -> sha256 as computed by intake (S1)."""
        base = root if root.is_dir() else root.parent
        for rel, sha in files.items():
            self.put_file(base / rel, sha)

    def write_manifest(self, artifact_id: str, files: dict[str, str], distribution: dict[str, str] | None = None) -> None:
        d = self.root / "manifests"
        d.mkdir(parents=True, exist_ok=True)
        body = {"artifact_id": artifact_id, "files": files}
        if distribution:
            body["distribution"] = distribution
        (d / f"{artifact_id.replace(':', '_')}.json").write_text(json.dumps(body, indent=2, sort_keys=True))

    def manifest(self, artifact_id: str) -> dict | None:
        p = self.root / "manifests" / f"{artifact_id.replace(':', '_')}.json"
        return json.loads(p.read_text()) if p.is_file() else None

    def materialise(self, files: dict[str, str], dest: Path) -> None:
        """Write an artifact's files from the store into `dest`, checking each hash on the way out."""
        for rel, sha in files.items():
            src = self.blob_path(sha)
            target = dest / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(src, target)
            if hashlib.sha256(target.read_bytes()).hexdigest() != sha:
                raise ValueError(f"store blob {sha[:12]} for {rel} is corrupt")
