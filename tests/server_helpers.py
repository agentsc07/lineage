"""Builders shared by the Track B server tests."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from lineage.schemas.finding import Evidence, Finding
from lineage.schemas.passport import (
    Contents, Passport, PassportBody, SignedPassport, Signer, SourceRef, Subject, sha256_hex,
)
from lineage_server import trust

NOW = datetime(2026, 10, 26, 9, 0, tzinfo=timezone.utc)
KEY = Ed25519PrivateKey.generate()


def make_signed(
    name: str,
    kind: str = "package",
    version: str = "1.0.0",
    parents: list[str] | None = None,
    trust_level: str = "inspected",
    risk: int = 0,
    repo: str | None = None,
    files: dict[str, str] | None = None,
    key: Ed25519PrivateKey = KEY,
) -> SignedPassport:
    digest = sha256_hex(f"{name}@{version}".encode())
    body = PassportBody(
        artifact_type=kind,  # type: ignore[arg-type]
        name=name,
        version=version,
        source=SourceRef(hub="test", repo=repo or f"apollo/{name}"),
        contents=Contents(merkle_root=digest, files=files or {f"{name}.dat": digest}),
        parents=parents or [],
        trust_level=trust_level,  # type: ignore[arg-type]
        findings_digest=sha256_hex(b"[]"),
        risk_score=risk,
        issued_by=Signer(name="tests", key_id=trust.key_id(key.public_key())),
        issued_at=NOW,
    )
    return trust.sign_passport(
        Passport(subject=[Subject(name=name, digest={"sha256": digest})], predicate=body), key
    )


def finding(fid: str = "X.TEST", severity: str = "low", score: int = 5, category: str = "code", **kw) -> Finding:
    return Finding(
        id=fid, title=fid, severity=severity, category=category, stage=kw.pop("stage", "S3"),  # type: ignore[arg-type]
        evidence=[Evidence(kind="field", ref="test", detail=kw.pop("detail", ""))],
        score=score, source=kw.pop("source", "deterministic"), **kw,
    )


def ago(**kw) -> datetime:
    return NOW - timedelta(**kw)
