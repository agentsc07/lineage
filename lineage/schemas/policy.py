"""PolicyPack: the organisation's rules, loaded from YAML (BUILD_PLAN §2.3)."""
from __future__ import annotations

from datetime import date, datetime
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, Field

from lineage.schemas.finding import Severity
from lineage.schemas.passport import TrustLevel, canonical_json, sha256_hex


class EnvPolicy(BaseModel):
    min_trust: TrustLevel
    max_risk: int = Field(ge=0, le=100)


class Publishers(BaseModel):
    allow: list[str] = Field(default_factory=list)
    block: list[str] = Field(default_factory=list)  # glob patterns, e.g. "*-official-mirror"


class ModelFiles(BaseModel):
    allow_pickle: bool = False


class DataRules(BaseModel):
    pii_allowed: bool = False
    residency: list[str] = Field(default_factory=list)


class Thresholds(BaseModel):
    allow: int = Field(ge=0, le=100)  # score <= allow -> allow
    quarantine: int = Field(ge=0, le=100)  # allow < score <= quarantine -> quarantine; above -> block


class TrustedPublisher(BaseModel):
    """A signing key the organisation trusts, and the sources it may speak for (fnmatch globs such as `hf:nvidia/*`)."""

    name: str
    key: str  # ed25519 public key, hex
    scope: list[str] = Field(default_factory=list)


def _default_unrun() -> dict[str, dict[str, Severity]]:
    return {"default": {"dev": "info", "staging": "medium", "prod": "high"}}


class PolicyException(BaseModel):
    artifact: str
    approver: str
    reason: str
    expires: date | datetime


class PolicyPack(BaseModel):
    org: str
    environments: dict[str, EnvPolicy]
    publishers: Publishers = Field(default_factory=Publishers)
    licences_allowed: list[str] = Field(default_factory=list)
    cooldown_days: dict[Literal["package", "model", "dataset", "tool"], int] = Field(default_factory=dict)
    banned_capabilities: list[str] = Field(default_factory=list)
    max_vuln_severity: dict[str, Severity] = Field(default_factory=dict)  # per environment
    require_human_approval: list[str] = Field(default_factory=list)  # "tool" or "model:prod"
    model_files: ModelFiles = Field(default_factory=ModelFiles)
    data: DataRules = Field(default_factory=DataRules)
    thresholds: Thresholds
    exceptions: list[PolicyException] = Field(default_factory=list)
    compliance_map: dict[str, list[str]] = Field(default_factory=dict)  # control -> finding categories
    # Severity of `CHECK.NOT_RUN.<NAME>` per environment; `default` covers names without their own entry.
    unrun_checks: dict[str, dict[str, Severity]] = Field(default_factory=_default_unrun)
    trusted_publishers: list[TrustedPublisher] = Field(default_factory=list)
    revoked_keys: list[str] = Field(default_factory=list)  # key ids
    # How long a client may keep using a cached attestation when the registry is unreachable. 0 = fail closed.
    offline_grace_hours: dict[str, int] = Field(default_factory=lambda: {"dev": 24, "staging": 6, "prod": 0})

    @classmethod
    def from_yaml(cls, path: str | Path) -> "PolicyPack":
        return cls.model_validate(yaml.safe_load(Path(path).read_text()))

    def to_yaml(self) -> str:
        return yaml.safe_dump(self.model_dump(mode="json"), sort_keys=False)

    @property
    def version(self) -> str:
        """Content-addressed policy version, recorded on every Decision as `policy_version`."""
        return "pp:" + sha256_hex(canonical_json(self))[:16]
