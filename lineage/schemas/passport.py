"""Passport: an in-toto Statement with predicate lineage.dev/passport/v1 (BUILD_PLAN §2.2).

`passport_id = "lp:" + sha256(canonical_json(passport))`. The signature is NOT part of the id,
so the same statement keeps one id no matter who signs it.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from lineage.schemas.fact import Fact

ArtifactType = Literal["dataset", "model", "package", "tool", "agent"]
# Ordered low to high. Trust comes only from evidence (REFACTOR_SPEC section 2); human approval is an exception, not a level.
TrustLevel = Literal["unknown", "origin_verified", "signed", "recorded"]
ActionKind = Literal["train", "fine-tune", "quantize", "intake", "publish"]

STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PREDICATE_TYPE = "https://lineage.dev/passport/v1"


def _jsonable(obj: Any) -> Any:
    """Plain-JSON form of a model/dict: datetimes become UTC `...Z` strings, aliases are used."""
    if isinstance(obj, BaseModel):
        obj = obj.model_dump(mode="json", by_alias=True)
    return obj


def canonical_json(obj: BaseModel | dict | list) -> bytes:
    """Deterministic JSON bytes: sorted keys, no whitespace, UTF-8, aliases, nulls kept."""
    return json.dumps(
        _jsonable(obj), sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class Subject(BaseModel):
    name: str
    digest: dict[str, str]  # {"sha256": "..."}


class SourceRef(BaseModel):
    hub: str | None = None  # "huggingface" | "pypi" | "npm" | "github" | ...
    repo: str | None = None  # "BerriAI/litellm"
    commit: str | None = None
    url: str | None = None


class Contents(BaseModel):
    merkle_root: str
    files: dict[str, str] = Field(default_factory=dict)  # path -> sha256
    tensors: dict[str, str] | None = None  # tensor name -> sha256 (models only)


class Action(BaseModel):
    kind: ActionKind
    command: list[str] | None = None
    env_sbom_digest: str | None = None


class SbomComponent(BaseModel):
    """CycloneDX-style component; `purl` looks like `pkg:pypi/torch@2.4.1`."""

    name: str
    version: str
    purl: str


class Signer(BaseModel):
    name: str
    key_id: str | None = None


class PassportBody(BaseModel):
    artifact_type: ArtifactType
    name: str
    version: str
    source: SourceRef
    contents: Contents
    parents: list[str] = Field(default_factory=list)  # passport ids
    action: Action | None = None
    trust_level: TrustLevel = "unknown"
    findings_digest: str  # sha256 of canonical JSON of the findings list
    risk_score: int = Field(ge=0, le=100)
    certificates: list[str] = Field(default_factory=list)  # notary cert ids
    # Passport v2 (all optional, so v1 passports still parse): what a `lineage run` read and what it ran with.
    inputs: dict[str, str] = Field(default_factory=dict)  # path -> sha256 of every file the run read
    sbom: list[SbomComponent] = Field(default_factory=list)
    facts: list[Fact] = Field(default_factory=list)  # what the creator asserts; `signed` only if the signature is in scope
    issued_by: Signer
    issued_at: datetime
    expires_at: datetime | None = None


class Passport(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    # pydantic forbids leading-underscore field names, so `_type` is an alias.
    type_: str = Field(default=STATEMENT_TYPE, alias="_type")
    subject: list[Subject]
    predicateType: str = PREDICATE_TYPE
    predicate: PassportBody

    def canonical_json(self) -> bytes:
        return canonical_json(self)

    @property
    def passport_id(self) -> str:
        return "lp:" + sha256_hex(self.canonical_json())


class SignedPassport(BaseModel):
    passport: Passport
    signature: str  # base64 Ed25519 signature over passport.canonical_json()
    key_id: str

    @property
    def passport_id(self) -> str:
        return self.passport.passport_id
