"""Intake pipeline S1-S7 per artifact type.

Each stage emits a `started` event and then `completed` / `skipped` / `failed`; the S6 `completed` event carries
the Decision. Scanners come from the registry in `lineage.intake.inspectors`; the GPU worker is optional and its
absence degrades to `info` findings. Nothing here raises for a bad artifact: a stage that blows up becomes a
`failed` event plus a finding, and the pipeline still reaches a decision.

One mandatory flow (REFACTOR_SPEC P2): every stage and every check for the artifact's type runs. A check that cannot
run emits `CHECK.NOT_RUN.<name>`; the policy prices it per environment.

Facts (P1): metadata is stored with a provenance class. What the uploader or a file inside the artifact says
(`claims`, `lineage.meta.json`, `config.json`, the README) is `declared` and can only add risk. What a hub told us
(`hub=`) is `fetched`; what a verified in-scope passport says is `signed`.

Conventions for local artifacts:
- `passport.json` (or `<file>.passport.json`) next to the artifact is a creator passport it ships with, excluded from the
  artifact's own file hashes. A directory's passport may also sit beside it as `<dir>.passport.json`.
- `lineage.meta.json` is no longer an input: it is hashed like any other file and its content becomes `declared` facts.
- A ref that is not a local path is a remote reference whose bytes we do not have: `CHECK.NOT_RUN.ACQUIRE` (a hard
  block). Real fetching arrives with the `hf:` / `pypi:` sources.
"""
from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Iterator
from datetime import datetime, timedelta, timezone
from pathlib import Path

from lineage.intake import inspectors as insp
from lineage.intake.inspectors import IntakeContext
from lineage.intake.hub import Hub
from lineage.intake.registry import NullRegistry, Registry
from lineage.store import Store
from lineage.policy.engine import apply_unrun_costs, decide
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
    ("S0", "Acquire"), ("S1", "Identify"), ("S2", "Provenance"), ("S3", "Static inspection"), ("S4", "Deep inspection"),
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


_META_KEYS = {"licence": "licence", "license": "licence", "released_at": "released_at", "publisher": "publisher",
              "claimed_base": "base_model", "base_model": "base_model", "description": "description", "summary": "description",
              "repo": "source_repo", "name": "name", "version": "version"}


def add_dict_facts(ctx: IntakeContext, meta: dict, provenance: str, source: str) -> None:
    for k, v in meta.items():
        key = _META_KEYS.get(k)
        if key and isinstance(v, (str, int, float)):
            ctx.add_fact(key, str(v), provenance, source)
    repo = meta.get("repo")
    if repo and "/" in str(repo):
        ctx.add_fact("publisher", str(repo).split("/")[0], provenance, source)
    if meta.get("urls") and isinstance(meta["urls"], list) and isinstance(meta["urls"][0], dict):
        ctx.add_fact("released_at", meta["urls"][0].get("upload_time_iso_8601"), provenance, source)


def _identify(ctx: IntakeContext, claims: dict | None, hub: Hub | None, claimed_origin: str | None,
              uploader: str) -> tuple[str, list[Finding]]:
    out: list[Finding] = []
    ref = ctx.ref
    p = Path(ref).expanduser()
    if p.exists():
        ctx.path = p.resolve()
    elif _looks_like_path(ref):
        out.append(insp.make_finding("INTAKE.REF.NOT_FOUND", f"Path {ref} does not exist", "high", "integrity", "S1",
                                     [Evidence(kind="field", ref="ref", detail=ref)]))

    root = ctx.root
    # declared: uploader claims, and a lineage.meta.json that happens to be inside the upload
    if root and (root / "lineage.meta.json").is_file():
        add_dict_facts(ctx, _load_json(root / "lineage.meta.json"), "declared", "file lineage.meta.json in upload")
    if claims:
        add_dict_facts(ctx, claims, "declared", f"upload by {uploader}")
    # fetched: what a hub says about this artifact. Facts about a *claimed* origin are held back until the hashes match
    # (S2a); a test/bench/demo hub that vouches for local bytes (`trusted_local`) is the only shortcut.
    ctx.hub, ctx.claimed_origin = hub, claimed_origin or ctx.claimed_origin
    if ctx.acquired is None and hub is not None:
        key = claimed_origin or (ctx.path.name if ctx.path else ref)
        record = hub.fetch(ctx.artifact_type, key)
        if record and claimed_origin:
            ctx.pending_record = dict(record)
        elif record and getattr(hub, "trusted_local", False):
            ctx.metadata = dict(record)
            add_dict_facts(ctx, record, "fetched", f"hub record for {key}")
            ctx.origin_verified = True

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
        if ctx.store is not None:  # P4: the exact bytes we inspect are the bytes we keep
            ctx.store.put_tree(ctx.path, ctx.files)
        if ctx.artifact_type == "model":
            ctx.tensors, bad = _tensor_hashes(ctx.path)
            out += bad
        for name in insp.CARD_NAMES:
            if root and (root / name).is_file():
                ctx.card_text = (root / name).read_text(errors="replace")
                ctx.add_fact("card_text", ctx.card_text, "declared", f"file {name} in upload")
                break
    elif not any(f.id == "CHECK.NOT_RUN.ACQUIRE" for f in ctx.findings):
        out.append(insp.not_run("ACQUIRE", f"the bytes of {ref} were not obtained, so nothing could be hashed or inspected", "S1"))

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
    name = ctx.fact_value("name", trusted_only=False) or name
    version = ctx.fact_value("version", trusted_only=False) or version
    if ctx.acquired is not None:  # named by the hub, not by the folder it was unpacked into
        rec = ctx.acquired.record  # type: ignore[attr-defined]
        name = rec.get("name") or (rec.get("repo") or name).split("/")[-1]
        version = rec.get("version") or str(rec.get("source_revision") or version)[:12]
    ctx.parents = ctx.parents or list(ctx.metadata.get("parents", []))

    if ctx.claimed:
        b = ctx.claimed.passport.predicate
        name, version, ctx.source = b.name, b.version, b.source
        if ctx.path is not None and not ctx.source.url:  # remember where the bytes are, for parent fingerprinting
            ctx.source = ctx.source.model_copy(update={"url": ctx.path.as_uri()})
        ctx.parents = list(dict.fromkeys(ctx.parents + b.parents))
    elif ctx.acquired is not None and ctx.path is not None:
        rec = ctx.acquired.record  # type: ignore[attr-defined]
        pypi = (ctx.claimed_origin or "").startswith("pypi:")
        ctx.source = SourceRef(hub="pypi" if pypi else "huggingface", repo=rec.get("repo") or name, commit=rec.get("source_revision"),
                               url=ctx.path.as_uri())
    elif ctx.path is None and "/" in ref and "==" not in ref:
        ctx.source = SourceRef(hub="huggingface", repo=ref)
    elif ctx.path is None:
        ctx.source = SourceRef(hub="pypi", repo=ctx.fact_value("source_repo", trusted_only=False))
    else:
        ctx.source = SourceRef(hub="local", repo=ctx.fact_value("source_repo", trusted_only=False), url=ctx.path.as_uri())
    ctx.name, ctx.version = name, version
    ctx.source_id = insp.source_id_of(ctx.source.hub, ctx.source.repo) or f"upload:{name}"

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
        if stage in ("S3", "S4", "S5") and ctx.path is None:
            return "skipped", [], "no bytes to inspect (CHECK.NOT_RUN.ACQUIRE)"
        found: list[Finding] = []
        base = ctx.findings
        for name, fn in scanners:
            ctx.findings = base + found  # later scanners see what earlier ones found
            found += insp.run_inspector(name, fn, ctx, stage)
        ctx.findings = base
        real = [f for f in found if f.severity != "info"]
        not_run = [f for f in found if f.id.startswith("CHECK.NOT_RUN.")]
        extra = f", {len(not_run)} check(s) did not run" if not_run else ""
        return "completed", found, f"{len(scanners)} scanner(s), {len(real)} finding(s){extra}"

    return run


def _trust(ctx: IntakeContext) -> TrustLevel:
    """Trust comes only from evidence (REFACTOR_SPEC section 2). Inspecting a file never raises it: an inspected
    unknown file stays `unknown`. `origin_verified` is granted by the origin check (R2.4) and by fetching."""
    if ctx.signature_in_scope:
        body = ctx.claimed.passport.predicate  # type: ignore[union-attr]
        if body.action and body.action.kind in ("train", "fine-tune", "build") and body.inputs and body.sbom:
            return "recorded"
        return "signed"
    if ctx.origin_verified:
        return "origin_verified"
    return "unknown"


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
        facts=[f for fs in ctx.facts.values() for f in fs],
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
    claims: dict | None = None,
    hub: Hub | None = None,
    claimed_origin: str | None = None,
    uploader: str = "anonymous",
    source: str | None = None,
    store: Store | None = None,
    work_dir: Path | None = None,
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
    ctx.store = store

    def event(stage: str, status: StageStatus, findings: list[Finding] | None = None, message: str = "",
              decision: Decision | None = None) -> StageEvent:
        return StageEvent(job_id=job_id, stage=stage, name=dict(STAGES)[stage], status=status,  # type: ignore[arg-type]
                          findings=findings or [], message=message, decision=decision, ts=datetime.now(timezone.utc))

    steps: dict[str, Callable[[IntakeContext], tuple[StageStatus, list[Finding], str]]] = {
        "S2": _stage_scanners("S2"), "S3": _stage_scanners("S3"), "S4": _stage_scanners("S4"), "S5": _stage_scanners("S5"),
    }
    steps["S0"] = lambda c: _s0(c, source, hub, work_dir)
    steps["S1"] = lambda c: _s1(c, claims, hub, claimed_origin, uploader)

    for stage in ("S0", "S1", "S2", "S3", "S4", "S5"):
        yield event(stage, "started")
        try:
            status, found, message = steps[stage](ctx)
        except Exception as e:  # noqa: BLE001 - the demo must never crash
            status, message = "failed", f"{type(e).__name__}: {e}"
            found = [insp.make_finding("INTAKE.STAGE.ERROR", f"Stage {stage} failed: {message}"[:300], "high", "policy", stage)]
        found = apply_unrun_costs(found, environment, policy)  # events show what an unrun check costs here
        ctx.findings = ctx.findings + found
        yield event(stage, status, found, message)

    # S6 Decide
    yield event("S6", "started")
    findings = apply_unrun_costs(ctx.findings, environment, policy)
    ctx.released_at = _parse_time(ctx.fact_value("released_at"))  # trusted facts only: a declared date never clears a cooldown
    trust = _trust(ctx)
    passport = _build_passport(ctx, findings, trust, clock(), policy)
    signed = ctx.registry.sign(passport)
    decision = decide(passport.predicate, findings, environment, policy, clock(), artifact_id=signed.passport_id,
                      released_at=ctx.released_at, policy_expired=policy_expired)
    yield event("S6", "completed", [], f"{decision.outcome}: {decision.reasons[0] if decision.reasons else ''}", decision)

    # S7 Admit (every outcome is recorded; only allow / allow_with_conditions are admitted)
    yield event("S7", "started")
    try:
        ctx.registry.record(signed, findings, decision, released_at=ctx.released_at, tool_pin=_tool_pin(ctx),
                            meta={"requester": uploader, "source": source or ref, "claimed_origin": ctx.claimed_origin,
                                  "claims": claims, "distribution": ctx.distribution, "source_id": ctx.source_id,
                                  "signer_key": ctx.claimed.key_id if ctx.claimed and ctx.signature_in_scope else None,
                                  "graph_refs": _graph_refs(ctx)})
        if ctx.store is not None and ctx.path is not None:
            ctx.store.write_manifest(signed.passport_id, ctx.files, ctx.distribution)
        yield event("S7", "completed", [], f"{signed.passport_id}: {STATUS_WORDS[decision.outcome]}")
    except Exception as e:  # noqa: BLE001
        yield event("S7", "failed", [], f"could not record result: {type(e).__name__}: {e}")


def _graph_refs(ctx: IntakeContext) -> list[dict]:
    """Everything this artifact references that should be an edge or a ghost node (REFACTOR_SPEC 6.1)."""
    refs = list(ctx.graph_refs)  # package dependencies, from S4
    base = ctx.fact_value("base_model")  # fetched or signed, never declared
    if base and not any(f.id == "MODEL.PARENT.CLAIM_MISMATCH" for f in ctx.findings):
        refs.append({"kind": "derived_from", "type": "model", "name": base.split("/")[-1], "ref": f"base model {base}"})
    if ctx.signature_in_scope and ctx.claimed is not None:
        body = ctx.claimed.passport.predicate
        refs += [{"kind": "built_with", "type": "package", "name": c.name, "version": c.version, "ref": c.purl} for c in body.sbom]
        refs += [{"kind": "trained_on", "type": "dataset", "file_sha": sha, "match_only": True, "name": path, "ref": path}
                 for path, sha in body.inputs.items()]
    return refs


def _s0(ctx: IntakeContext, source: str | None, hub: Hub | None, work_dir: Path | None) -> tuple[StageStatus, list[Finding], str]:
    """S0 Acquire. Uploads are already on disk; `hf:`, `hf-dataset:` and `pypi:` sources are fetched by Lineage itself, which is
    what makes their facts `fetched` and their origin verified. A wheel upload is unpacked for inspection and kept as the
    distribution to serve."""
    import tempfile
    import uuid

    from lineage.intake import fetch

    work = (work_dir or Path(tempfile.gettempdir()) / "lineage-fetch") / uuid.uuid4().hex[:10]
    kw = {"base_url": getattr(hub, "base_url", None) or None, "client": getattr(hub, "client", None)}
    if source and source.startswith(("hf:", "hf-dataset:", "pypi:")):
        ctx.claimed_origin = source
        try:
            if source.startswith("pypi:"):
                acq = fetch.fetch_pypi(source, work / "pkg", **kw)
            else:
                acq = fetch.fetch_hf(source, work / source.split(":", 1)[1].split("@")[0].split("/")[-1], allow_pickle=ctx.policy.model_files.allow_pickle, **kw)
        except fetch.AcquireError as e:
            return "failed", [insp.not_run("ACQUIRE", str(e), "S0")], f"could not fetch {source}"
        ctx.acquired, ctx.ref = acq, str(acq.path)
        ctx.distribution = acq.distribution
        if acq.distribution and acq.dist_path and ctx.store is not None:
            ctx.store.put_file(acq.dist_path, acq.distribution["sha256"])
        ctx.origin_verified = True
        ctx.metadata = dict(acq.record)
        add_dict_facts(ctx, acq.record, "fetched", f"hub api for {source}")
        found = [insp.make_finding(fid, title, sev, "integrity", "S0") for fid, title, sev in acq.notes]  # type: ignore[arg-type]
        if acq.skipped_files:
            found.append(insp.make_finding("MODEL.FORMAT.PICKLE_NOT_FETCHED", f"{len(acq.skipped_files)} large pickle file(s) were not downloaded: "
                                           + ", ".join(acq.skipped_files[:3]), "high", "model", "S0",
                                           [Evidence(kind="file_line", ref=p) for p in acq.skipped_files[:5]]))
        return "completed", found, f"fetched {source} ({len(list(acq.path.rglob('*')))} entries)"
    p = Path(ctx.ref).expanduser()
    if p.is_file() and ctx.artifact_type == "package" and p.suffix in (".whl", ".zip", ".gz"):
        try:
            fetch.safe_extract(p, work / "pkg")
        except fetch.AcquireError as e:
            return "failed", [insp.not_run("ACQUIRE", str(e), "S0")], "could not unpack the upload"
        ctx.distribution = {"filename": p.name, "sha256": _hash_file(p)}
        ctx.ref = str(work / "pkg")
        if ctx.store is not None:
            ctx.store.put_file(p, ctx.distribution["sha256"])
        return "completed", [], f"unpacked {p.name} for inspection; the wheel itself is kept for the index"
    return "completed", [], "bytes already on disk (upload)" if p.exists() else "no bytes yet"


def _s1(ctx: IntakeContext, claims: dict | None, hub: Hub | None, claimed_origin: str | None,
        uploader: str) -> tuple[StageStatus, list[Finding], str]:
    msg, found = _identify(ctx, claims, hub, claimed_origin, uploader)
    return ("failed" if any(f.id == "INTAKE.REF.NOT_FOUND" for f in found) else "completed"), found, msg


def run_to_decision(*args, **kwargs) -> tuple[Decision, list[StageEvent]]:
    """Drain `run_intake` and return (decision, events). Convenience for the CLI, seed script and tests."""
    events = list(run_intake(*args, **kwargs))
    decision = next(e.decision for e in events if e.decision)
    return decision, events
