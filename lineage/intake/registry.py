"""What the intake pipeline needs from a registry. `lineage_server.registry.SqliteRegistry` implements it;
`NullRegistry` makes the pipeline usable standalone (the CLI's `lineage intake` without a server)."""
from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Protocol

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from lineage.schemas.decision import Decision
from lineage.schemas.finding import Finding
from lineage.schemas.passport import Passport, SignedPassport


class Registry(Protocol):
    def find_by_digest(self, merkle_root: str) -> str | None:
        """Passport id of an already-registered artifact with this Merkle root."""

    def artifact_status(self, passport_id: str) -> str | None:
        """`Artifact.status` of a registered artifact, or None if it is unknown."""

    def trusted_key(self, key_id: str) -> Ed25519PublicKey | None:
        """Public key of a signer we trust, by key id."""

    def reference_models(self) -> dict[str, tuple[str, Path]]:
        """Admitted models whose weights are on local disk: passport id -> (label, directory). The bank that
        parent fingerprinting compares an incoming model against."""

    def sign(self, passport: Passport) -> SignedPassport:
        """Sign with the organisation's key."""

    def record(
        self,
        signed: SignedPassport,
        findings: list[Finding],
        decision: Decision,
        *,
        released_at: datetime | None = None,
        tool_pin: dict[str, str] | None = None,
    ) -> None:
        """Persist the intake result."""


class NullRegistry:
    """Knows nothing, trusts nobody, signs nothing (signature is empty), stores nothing."""

    def find_by_digest(self, merkle_root: str) -> str | None:
        return None

    def artifact_status(self, passport_id: str) -> str | None:
        return None

    def trusted_key(self, key_id: str) -> Ed25519PublicKey | None:
        return None

    def reference_models(self) -> dict[str, tuple[str, Path]]:
        return {}

    def sign(self, passport: Passport) -> SignedPassport:
        return SignedPassport(passport=passport, signature="", key_id="unsigned")

    def record(self, signed, findings, decision, *, released_at=None, tool_pin=None) -> None:
        return None
