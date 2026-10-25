"""Intake pipeline S1-S7 per artifact type.

Each stage emits a `started` event and then `completed` / `skipped` / `failed`; the S6 `completed` event carries
the Decision. Scanners come from the registry in `lineage.intake.inspectors`; the GPU worker is optional and its
absence degrades to `info` findings. Nothing here raises for a bad artifact: a stage that blows up becomes a
`failed` event plus a finding, and the pipeline still reaches a decision.

Conventions for local artifacts:
- `passport.json` (or `<file>.passport.json`) next to the artifact is a signed passport it ships with.
- `lineage.meta.json` is a registry-metadata snapshot (`released_at`, `licence`, `repo`, `claimed_base`, ...).
- Both are excluded from the artifact's own file hashes. A directory's passport may also sit beside it as
  `<dir>.passport.json` (what `lineage sign` writes by default).
- A ref that is not a local path (a hub id or `pkg==1.2.3`) is a *remote reference*: Track B does not download
  it, so it is recorded with trust `unknown` and a finding saying its bytes were not inspected.
"""
from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Iterator
from datetime import datetime, timedelta, timezone
from pathlib import Path

from lineage.intake import inspectors as insp
from lineage.intake.inspectors import IntakeContext
from lineage.intake.registry import NullRegistry, Registry
from lineage.policy.engine import decide
from lineage.risk import risk_score
from lineage.schemas.artifact import StageEvent, StageStatus
from lineage.schemas.decision import Decision
from lineage.schemas.finding import Evidence, Finding
from lineage.schemas.passport import (
    Action, ArtifactType, Contents, Passport, PassportBody, SignedPassport, Signer, SourceRef, Subject,
    TrustLevel, canonical_json, sha256_hex,
)
from lineage.schemas.policy import PolicyPack

STAGES = [
    ("S1", "Identify"), ("S2", "Provenance"), ("S3", "Static inspection"), ("S4", "Deep inspection"),
    ("S5", "LLM review"), ("S6", "Decide"), ("S7", "Admit"),
]
SIDECARS = insp.SIDECARS
PASSPORT_LIFETIME = timedelta(days=90)
STATUS_WORDS = {
    "allow": "admitted", "allow_with_conditions": "admitted with conditions",
    "quarantine": "quarantined, waiting for cooldown or a human", "block": "blocked",
}


# ------------------------------------------------------------------------------------------------ hashing (S1)
def _hash_file(path: Path) -> str:
    try:
        from lineage.hashing.files import hash_file

        return hash_file(path)
    except NotImplementedError:
        h = hashlib.sha256()
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(8 * 1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()


def _hash_files(root: Path) -> dict[str, str]:
    """POSIX relative path -> sha256 for the artifact's own files (sidecars excluded)."""
    if root.is_file():
        return {root.name: _hash_file(root)}
    paths = sorted(p for p in root.rglob("*") if p.is_file() and p.name not in SIDECARS and ".git" not in p.parts)
    return {p.relative_to(root).as_posix(): _hash_file(p) for p in paths}


def _merkle_root(leaves: dict[str, str]) -> str:
    try:
        from lineage.hashing.merkle import merkle_root

        return merkle_root(leaves)
    except NotImplementedError:
        level = [sha256_hex(n.encode() + b"\x00" + d.encode()) for n, d in sorted(leaves.items())] or [sha256_hex(b"")]
        while len(level) > 1:
            if len(level) % 2:
                level.append(level[-1])
            level = [sha256_hex((level[i] + level[i + 1]).encode()) for i in range(0, len(level), 2)]
        return level[0]


def _tensor_hashes(root: Path) -> tuple[dict[str, str] | None, list[Finding]]:
    """Per-tensor hashes for safetensors files. A file whose header does not parse is reported, never raised:
    a malformed weights file is exactly what a hostile artifact looks like."""
    if not root.is_dir():
        return None, []
    try:
        from lineage.hashing.tensors import hash_safetensors
    except ImportError:
        return None, []
    out: dict[str, str] = {}
    problems: list[Finding] = []
    for p in sorted(root.rglob("*.safetensors")):
        try:
            out.update(hash_safetensors(p))
        except NotImplementedError:
            return None, problems
        except (ValueError, OSError, KeyError) as e:
            problems.append(insp.make_finding(
                "MODEL.FORMAT.MALFORMED_SAFETENSORS", f"{p.relative_to(root).as_posix()} is not a valid safetensors file: {str(e)[:100]}",
                "high", "model", "S1", [Evidence(kind="file_line", ref=p.relative_to(root).as_posix(), detail=str(e)[:160])]))
    return out or None, problems


# ------------------------------------------------------------------------------------------------ S1 helpers
def _looks_like_path(ref: str) -> bool:
    return ref.startswith(("/", "./", "../", "~"))


def _parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    t = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return t if t.tzinfo else t.replace(tzinfo=timezone.utc)


def _load_json(path: Path) -> dict:
    return json.loads(path.read_text())


def _identify(ctx: IntakeContext, explicit_meta: dict | None) -> tuple[str, list[Finding]]:
    out: list[Finding] = []
    ref = ctx.ref
    p = Path(ref).expanduser()
    if p.exists():
        ctx.path = p.resolve()
    elif _looks_like_path(ref):
        out.append(insp.make_finding("INTAKE.REF.NOT_FOUND", f"Path {ref} does not exist", "high", "integrity", "S1",
                                     [Evidence(kind="field", ref="ref", detail=ref)]))

    root = ctx.root
    meta: dict = {}
    if root and (root / "lineage.meta.json").exists():
        meta.update(_load_json(root / "lineage.meta.json"))
    meta.update(explicit_meta or {})
    ctx.metadata = meta

    if ctx.path is not None:
        # `<name>.passport.json` beside the artifact is what `lineage sign` writes and `lineage.load` discovers;
        # `passport.json` inside a directory is also accepted.
        candidates = [ctx.path.with_name(ctx.path.name + ".passport.json")]
        if ctx.path.is_dir():
            candidates.append(ctx.path / "passport.json")
        sidecar = next((c for c in candidates if c.exists()), candidates[0])
        if sidecar.exists():
            try:
                ctx.claimed = SignedPassport.model_validate_json(sidecar.read_text())
            except ValueError as e:
                out.append(insp.make_finding("INTAKE.PASSPORT.MALFORMED", f"Shipped passport cannot be parsed: {str(e)[:120]}",
                                             "medium", "provenance", "S1", [Evidence(kind="file_line", ref=sidecar.name)]))
        ctx.files = _hash_files(ctx.path)
        if ctx.artifact_type == "model":
            ctx.tensors, bad = _tensor_hashes(ctx.path)
            out += bad
        for name in insp.CARD_NAMES:
            if root and (root / name).is_file():
                ctx.card_text = (root / name).read_text(errors="replace")
                break
    else:
        out.append(insp.make_finding("PROV.UNVERIFIED.REMOTE_REF", "Remote reference: bytes were not fetched, so nothing could be "
                                     "hashed or inspected", "medium", "provenance", "S1", [Evidence(kind="field", ref="ref", detail=ref)]))

    # name / version / source / parents
    name, version = ref, "0.0.0"
    if "==" in ref and ctx.path is None:
        name, version = ref.split("==", 1)
    elif ctx.path is not None:
        name = ctx.path.name if ctx.path.is_dir() else ctx.path.stem
    manifest = root / "manifest.json" if root and ctx.artifact_type == "tool" else None
    agent_file = (ctx.path if ctx.path and ctx.path.is_file() else root / "agent.json") if root and ctx.artifact_type == "agent" else None
    for doc in (manifest, agent_file):
        if doc and doc.is_file():
            d = _load_json(doc)
            name, version = d.get("name", name), d.get("version", version)
            if ctx.artifact_type == "agent":
                ctx.parents = list(d.get("parts", []))
    name, version = meta.get("name", name), meta.get("version", version)
    ctx.parents = ctx.parents or list(meta.get("parents", []))
    ctx.released_at = _parse_time(meta.get("released_at") or (meta.get("urls") or [{}])[0].get("upload_time_iso_8601"))

    if ctx.claimed:
        b = ctx.claimed.passport.predicate
        name, version, ctx.source = b.name, b.version, b.source
        ctx.parents = list(dict.fromkeys(ctx.parents + b.parents))
    elif ctx.path is None and "/" in ref and "==" not in ref:
        ctx.source = SourceRef(hub="huggingface", repo=ref)
    elif ctx.path is None:
        ctx.source = SourceRef(hub="pypi", repo=meta.get("repo"))
    else:
        ctx.source = SourceRef(hub="local", repo=meta.get("repo"), url=ctx.path.as_uri())
    ctx.name, ctx.version = name, version

    msg = f"{name}@{version}"
    if ctx.path is not None:
        root_hash = _merkle_root(ctx.files)
        known = ctx.registry.find_by_digest(root_hash)
        msg += f": {len(ctx.files)} file(s) hashed, merkle root {root_hash[:12]}"
        if known:
            out.append(insp.make_finding("INTAKE.DIGEST.KNOWN", f"Identical contents are already registered as {known[:19]}", "info",
                                         "provenance", "S1", [Evidence(kind="field", ref=known)]))
    return msg, out


# ------------------------------------------------------------------------------------------------ stages
def _stage_scanners(stage: str) -> Callable[[IntakeContext], tuple[StageStatus, list[Finding], str]]:
    def run(ctx: IntakeContext) -> tuple[StageStatus, list[Finding], str]:
        scanners = insp.inspectors_for(ctx.artifact_type, stage)
        if stage in ("S4", "S5"):
            if not scanners:
                return "skipped", [], f"no deep checks for {ctx.artifact_type}"
            go, why = insp.needs_deep(ctx, ctx.findings)
            if not go:
                return "skipped", [], why
        found: list[Finding] = []
        base = ctx.findings
        for name, fn in scanners:
            ctx.findings = base + found  # later scanners see what earlier ones found
            found += insp.run_inspector(name, fn, ctx, stage)
        ctx.findings = base
        real = [f for f in found if f.severity != "info"]
        return "completed", found, f"{len(scanners)} scanner(s), {len(real)} finding(s)"

    return run


def _trust(ctx: IntakeContext) -> TrustLevel:
    if ctx.path is not None:
        return "inspected"
    verified = ctx.claimed is not None and not any(f.id.startswith("PROV.SIGNATURE") for f in ctx.findings)
    return "declared" if verified else "unknown"


def _build_passport(ctx: IntakeContext, findings: list[Finding], trust: TrustLevel, now: datetime, policy: PolicyPack) -> Passport:
    merkle = _merkle_root(ctx.files) if ctx.path is not None else sha256_hex(f"{ctx.artifact_type}:{ctx.ref}".encode())
    body = PassportBody(
        artifact_type=ctx.artifact_type,
        name=ctx.name,
        version=ctx.version,
        source=ctx.source,
        contents=Contents(merkle_root=merkle, files=ctx.files, tensors=ctx.tensors),
        parents=ctx.parents,
        action=Action(kind="intake"),
        trust_level=trust,
        findings_digest=sha256_hex(canonical_json([f.model_dump(mode="json") for f in findings])),
        risk_score=risk_score(findings, trust),
        certificates=ctx.claimed.passport.predicate.certificates if ctx.claimed else [],
        issued_by=Signer(name=policy.org),
        issued_at=now,
        expires_at=now + PASSPORT_LIFETIME,
    )
    return Passport(subject=[Subject(name=ctx.name, digest={"sha256": merkle})], predicate=body)


def _tool_pin(ctx: IntakeContext) -> dict[str, str] | None:
    if ctx.artifact_type != "tool" or ctx.root is None or not (ctx.root / "manifest.json").exists():
        return None
    from mcp_gateway.gateway import pin_tool

    return pin_tool(ctx.root / "manifest.json", ctx.root)


def run_intake(
    artifact_type: ArtifactType,
    ref: str,
    environment: str,
    policy: PolicyPack,
    job_id: str,
    *,
    registry: Registry | None = None,
    gpu_url: str | None = None,
    metadata: dict | None = None,
    now: datetime | None = None,
    policy_expired: bool = False,
) -> Iterator[StageEvent]:
    """Run stages in order, yielding one StageEvent per stage transition. The S6 event carries the Decision.

    Inspectors are looked up from a registry; GPU-worker failures degrade to an `info` Finding, never an exception.
    Raises ValueError up front if `environment` is not in the policy.
    """
    if environment not in policy.environments:
        raise ValueError(f"unknown environment {environment!r}; policy defines {sorted(policy.environments)}")
    clock = lambda: now or datetime.now(timezone.utc)  # noqa: E731
    ctx = IntakeContext(artifact_type=artifact_type, ref=ref, environment=environment, policy=policy,
                        registry=registry or NullRegistry(), now=clock(), gpu_url=gpu_url)

    def event(stage: str, status: StageStatus, findings: list[Finding] | None = None, message: str = "",
              decision: Decision | None = None) -> StageEvent:
        return StageEvent(job_id=job_id, stage=stage, name=dict(STAGES)[stage], status=status,  # type: ignore[arg-type]
                          findings=findings or [], message=message, decision=decision, ts=datetime.now(timezone.utc))

    steps: dict[str, Callable[[IntakeContext], tuple[StageStatus, list[Finding], str]]] = {
        "S2": _stage_scanners("S2"), "S3": _stage_scanners("S3"), "S4": _stage_scanners("S4"), "S5": _stage_scanners("S5"),
    }
    steps["S1"] = lambda c: _s1(c, metadata)

    for stage in ("S1", "S2", "S3", "S4", "S5"):
        yield event(stage, "started")
        try:
            status, found, message = steps[stage](ctx)
        except Exception as e:  # noqa: BLE001 - the demo must never crash
            status, message = "failed", f"{type(e).__name__}: {e}"
            found = [insp.make_finding("INTAKE.STAGE.ERROR", f"Stage {stage} failed: {message}"[:300], "high", "policy", stage)]
        ctx.findings = ctx.findings + found
        yield event(stage, status, found, message)

    # S6 Decide
    yield event("S6", "started")
    findings = ctx.findings
    trust = _trust(ctx)
    passport = _build_passport(ctx, findings, trust, clock(), policy)
    signed = ctx.registry.sign(passport)
    decision = decide(passport.predicate, findings, environment, policy, clock(), artifact_id=signed.passport_id,
                      released_at=ctx.released_at, policy_expired=policy_expired)
    yield event("S6", "completed", [], f"{decision.outcome}: {decision.reasons[0] if decision.reasons else ''}", decision)

    # S7 Admit (every outcome is recorded; only allow / allow_with_conditions are admitted)
    yield event("S7", "started")
    try:
        ctx.registry.record(signed, findings, decision, released_at=ctx.released_at, tool_pin=_tool_pin(ctx))
        yield event("S7", "completed", [], f"{signed.passport_id}: {STATUS_WORDS[decision.outcome]}")
    except Exception as e:  # noqa: BLE001
        yield event("S7", "failed", [], f"could not record result: {type(e).__name__}: {e}")


def _s1(ctx: IntakeContext, metadata: dict | None) -> tuple[StageStatus, list[Finding], str]:
    msg, found = _identify(ctx, metadata)
    return ("failed" if any(f.id == "INTAKE.REF.NOT_FOUND" for f in found) else "completed"), found, msg


def run_to_decision(*args, **kwargs) -> tuple[Decision, list[StageEvent]]:
    """Drain `run_intake` and return (decision, events). Convenience for the CLI, seed script and tests."""
    events = list(run_intake(*args, **kwargs))
    decision = next(e.decision for e in events if e.decision)
    return decision, events
