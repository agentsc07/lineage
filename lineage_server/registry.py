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
    def __init__(self, conn: sqlite3.Connection, signing_key: Ed25519PrivateKey):
        self.conn, self.key = conn, signing_key
        trust.trust_key(conn, signing_key.public_key(), "registry")

    def find_by_digest(self, merkle_root: str) -> str | None:
        return models.find_by_merkle_root(self.conn, merkle_root)

    def artifact_status(self, passport_id: str) -> str | None:
        art = models.artifact_row(self.conn, passport_id)
        return art.status if art else None

    def trusted_key(self, key_id: str) -> Ed25519PublicKey | None:
        return trust.trusted_key(self.conn, key_id)

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
    ) -> None:
        service.record(self.conn, signed, findings, decision, released_at=released_at, tool_pin=tool_pin)
