"""SQLite-backed implementation of `lineage.intake.registry.Registry`."""
from __future__ import annotations

import sqlite3
from datetime import datetime
from pathlib import Path
from urllib.parse import unquote, urlparse

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from lineage.schemas.decision import Decision
from lineage.schemas.finding import Finding
from lineage.schemas.passport import Passport, SignedPassport
from lineage_server import models, service, trust


class SqliteRegistry:
    def __init__(self, conn: sqlite3.Connection, signing_key: Ed25519PrivateKey, store=None):
        self.conn, self.key, self.store = conn, signing_key, store
        trust.trust_key(conn, signing_key.public_key(), "registry")

    def find_by_digest(self, merkle_root: str) -> str | None:
        return models.find_by_merkle_root(self.conn, merkle_root)

    def artifact_status(self, passport_id: str) -> str | None:
        art = models.artifact_row(self.conn, passport_id)
        return art.status if art else None

    def resolve_ref(self, ref: str) -> str | None:
        ref = ref.strip()
        if ref.startswith("lp:"):
            return ref if models.artifact_row(self.conn, ref) else None
        name, _, version = ref.partition("@")
        for a in models.list_artifacts(self.conn):  # newest first
            if a.name == name and (not version or a.version == version) and a.status not in ("rejected",):
                return a.id
        return None

    def trusted_key(self, key_id: str) -> Ed25519PublicKey | None:
        return trust.trusted_key(self.conn, key_id)

    def package_status(self, name: str, version: str | None = None) -> str | None:
        import re

        norm = lambda n: re.sub(r"[-_.]+", "-", n).lower()  # noqa: E731
        for a in models.list_artifacts(self.conn):
            if a.artifact_type == "package" and norm(a.name) == norm(name) and (version is None or a.version == version):
                return a.status
        return None

    def previous_version_path(self, artifact_type: str, name: str, dest: Path) -> Path | None:
        if self.store is None:
            return None
        for a in models.list_artifacts(self.conn):
            if a.artifact_type == artifact_type and a.name == name and a.status in ("admitted", "admitted_with_conditions"):
                man = self.store.manifest(a.id)
                if man:
                    self.store.materialise(man["files"], dest)
                    return dest
        return None

    def reference_models(self) -> dict[str, tuple[str, Path]]:
        out: dict[str, tuple[str, Path]] = {}
        for art in models.list_artifacts(self.conn):
            if art.artifact_type != "model" or art.status not in ("admitted", "admitted_with_conditions"):
                continue
            signed = models.get_signed_passport(self.conn, art.id)
            url = signed.passport.predicate.source.url if signed else None
            if url and url.startswith("file://"):
                path = Path(unquote(urlparse(url).path))
                if path.is_dir():
                    out[art.id] = (f"{art.name}@{art.version}", path)
        return out

    def sign(self, passport: Passport) -> SignedPassport:
        return trust.sign_passport(passport, self.key)

    def record(
        self,
        signed: SignedPassport,
        findings: list[Finding],
        decision: Decision,
        *,
        released_at: datetime | None = None,
        tool_pin: dict[str, str] | None = None,
        meta: dict | None = None,
    ) -> None:
        service.record(self.conn, signed, findings, decision, released_at=released_at, tool_pin=tool_pin, meta=meta)
