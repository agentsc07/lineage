"""Inspector registry for intake: which scanners run at which stage for which artifact type.

An inspector is `fn(ctx) -> list[Finding]`. Scanners that are not implemented yet, or that crash, never take
intake down: a missing one yields a `CHECK.NOT_RUN.*` finding, a crashing one a `medium` finding (a scanner that dies
on an artifact is itself suspicious, and must not turn into a silent pass).

One mandatory flow (REFACTOR_SPEC P2): every registered inspector runs for every artifact of its type. A check that
cannot run says so with `not_run(...)`; the policy (`unrun_checks`) decides what that costs per environment.
"""
from __future__ import annotations

import base64
import json
import logging
import re
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from fnmatch import fnmatchcase
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from lineage.intake import gpu
from lineage.intake.registry import Registry
from lineage.risk import SEVERITY_WEIGHT
from lineage.schemas.fact import Fact, best
from lineage.schemas.finding import Evidence, Finding, Severity
from lineage.schemas.gpu import (
    BehaviourDiffRequest, BehaviourDiffResponse, Claim, NotaryCheckRequest, NotaryCheckResponse,
    ParentRequest, ParentResponse, ReviewCardRequest, ReviewCodeRequest, ReviewResponse, SpectralRequest,
    SpectralResponse,
)
from lineage.schemas.passport import ArtifactType, SignedPassport, SourceRef
from lineage.schemas.policy import PolicyPack

log = logging.getLogger(__name__)
SIDECARS = {"passport.json"}  # a shipped passport is evidence, not part of the artifact's own bytes
PICKLE_SUFFIXES = (".pkl", ".pickle", ".pt", ".pth", ".bin", ".ckpt")
CARD_NAMES = ("README.md", "MODEL_CARD.md", "DATASET_CARD.md", "README")
SPECTRAL_HIGH, SPECTRAL_MEDIUM = 0.8, 0.5
DIVERGENCE_HIGH, DIVERGENCE_MEDIUM = 0.30, 0.10


@dataclass
class IntakeContext:
    artifact_type: ArtifactType
    ref: str
    environment: str
    policy: PolicyPack
    registry: Registry
    now: datetime
    gpu_url: str | None = None
    path: Path | None = None  # None: a remote reference whose bytes we do not have
    name: str = ""
    version: str = "0.0.0"
    source: SourceRef = field(default_factory=SourceRef)
    metadata: dict = field(default_factory=dict)  # what a hub returned for this artifact (`fetched` only; never uploader input)
    facts: dict[str, list[Fact]] = field(default_factory=dict)
    released_at: datetime | None = None  # the best *trusted* release date; None means the cooldown cannot be cleared
    claimed: SignedPassport | None = None  # passport shipped with the artifact (evidence until S2b verifies it)
    parents: list[str] = field(default_factory=list)
    files: dict[str, str] = field(default_factory=dict)  # computed sha256 per file
    card_text: str | None = None
    tensors: dict[str, str] | None = None
    findings: list[Finding] = field(default_factory=list)  # everything found so far
    gpu_down: bool = False
    previous: tuple[Path, str] | None = None  # (folder, version) of the release before this one, for diff-aware review
    signature_in_scope: bool = False  # S2b: a trusted key, in scope, hashes match
    origin_verified: bool = False  # every file matches what the hub published, or Lineage fetched the bytes itself
    graph_refs: list[dict] = field(default_factory=list)  # things this artifact references: become edges or ghost nodes (P6)
    store: object | None = None  # lineage.store.Store: where every inspected file is kept
    hub: object | None = None  # the Hub used for origin checks (S2a)
    claimed_origin: str | None = None  # what an upload says it is a copy of, e.g. `hf:org/name@rev`
    pending_record: dict | None = None  # hub record for the claimed origin: becomes `fetched` facts only if the hashes match
    acquired: object | None = None  # lineage.intake.fetch.Acquired when Lineage fetched the bytes itself
    distribution: dict | None = None  # {filename, sha256}: the wheel as distributed (served by /simple)
    source_id: str = ""  # `upload:<name>`, `hf:<repo>`, `pypi:<name>`: what trusted-publisher scopes are matched against

    @property
    def root(self) -> Path | None:
        return self.path if self.path and self.path.is_dir() else (self.path.parent if self.path else None)

    def add_fact(self, key: str, value: str | None, provenance: str, source: str) -> None:
        if value is None or value == "":
            return
        self.facts.setdefault(key, []).append(
            Fact(key=key, value=str(value), provenance=provenance, source=source, at=self.now))  # type: ignore[arg-type]

    def fact(self, key: str, trusted_only: bool = True) -> Fact | None:
        """Best fact for `key` by class: signed > fetched > computed > declared. `trusted_only` never returns a declared one."""
        return best(self.facts.get(key, []), trusted_only)

    def fact_value(self, key: str, trusted_only: bool = True) -> str | None:
        f = self.fact(key, trusted_only)
        return f.value if f else None

    @property
    def publisher(self) -> str | None:
        """The publisher according to the best trusted fact (never the uploader's word)."""
        return self.fact_value("publisher")


Inspector = Callable[[IntakeContext], list[Finding]]
INSPECTORS: dict[tuple[str, str], list[tuple[str, Inspector]]] = defaultdict(list)


def register(artifact_types: str | tuple[str, ...], stage: str) -> Callable[[Inspector], Inspector]:
    """Register under one type, a tuple of types, or "*" for all."""
    kinds = (artifact_types,) if isinstance(artifact_types, str) else artifact_types

    def deco(fn: Inspector) -> Inspector:
        for kind in kinds:
            INSPECTORS[(kind, stage)].append((fn.__name__, fn))
        return fn

    return deco


def inspectors_for(artifact_type: str, stage: str) -> list[tuple[str, Inspector]]:
    return INSPECTORS[("*", stage)] + INSPECTORS[(artifact_type, stage)]


def make_finding(
    fid: str, title: str, severity: Severity, category: str, stage: str,
    evidence: list[Evidence] | None = None, source: str = "deterministic", score: int | None = None, grounded: bool = True,
) -> Finding:
    return Finding(
        id=fid, title=title, severity=severity, category=category, stage=stage,  # type: ignore[arg-type]
        evidence=evidence or [], score=SEVERITY_WEIGHT[severity] if score is None else score,
        source=source, grounded=grounded,  # type: ignore[arg-type]
    )


def run_inspector(name: str, fn: Inspector, ctx: IntakeContext, stage: str) -> list[Finding]:
    try:
        return fn(ctx)
    except NotImplementedError:
        return [not_run(name, "scanner is not available in this build", stage)]
    except Exception as e:  # noqa: BLE001 - a crashing scanner must never become a silent pass
        return [make_finding(f"SCANNER.ERROR.{name.upper()}", f"Scanner '{name}' failed: {type(e).__name__}: {e}"[:300],
                             "medium", "policy", stage, [Evidence(kind="field", ref=name, detail=repr(e)[:200])])]


def not_run(name: str, why: str, stage: str, severity: Severity = "medium") -> Finding:
    """A check that could not run. The severity here is a placeholder: the policy's `unrun_checks` sets the real cost per
    environment (`lineage.policy.engine.apply_unrun_costs`)."""
    return make_finding(f"CHECK.NOT_RUN.{name.upper()}", f"Check {name.lower()} did not run: {why}", severity, "policy", stage,
                        [Evidence(kind="field", ref=name.lower(), detail=why[:200])])


def _levenshtein(a: str, b: str) -> int:
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


# ----------------------------------------------------------------------------------------------- S2 (all types)
def source_id_of(hub: str | None, repo: str | None) -> str | None:
    """`hf:org/name`, `pypi:name` for a source reference; None when it names nothing checkable."""
    if not repo:
        return None
    return {"huggingface": f"hf:{repo}", "hf": f"hf:{repo}", "pypi": f"pypi:{repo}"}.get(hub or "")


def _git_oid(path: Path) -> str:
    import hashlib

    data = path.read_bytes()
    return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()  # noqa: S324 - git's object id, not a security hash


def _promote_pending(ctx: IntakeContext, source: str) -> None:
    """The hashes match what the hub published, so what the hub says about that repo describes these bytes: `fetched`."""
    from lineage.intake.pipeline import add_dict_facts

    ctx.origin_verified = True
    if ctx.pending_record:
        add_dict_facts(ctx, ctx.pending_record, "fetched", source)
        ctx.metadata = dict(ctx.pending_record)
        ctx.pending_record = None


@register("*", "S2")
def origin_check(ctx: IntakeContext) -> list[Finding]:
    """S2a. Where did these bytes come from? An upload with a claimed origin is compared, file by file, with what that hub
    published at a pinned revision. Hints inside the artifact are shown as `declared` and never used for trust."""
    from lineage.intake.fetch import _wanted

    out: list[Finding] = []
    for hint, value in _hints(ctx):
        ctx.add_fact("source_repo", value, "declared", f"hint: {hint}")
        out.append(make_finding("PROV.ORIGIN.HINT", f"Suggested origin: {value} (from {hint}); not used for trust", "info", "provenance", "S2",
                                [Evidence(kind="field", ref=hint, detail=value)]))
    if ctx.acquired is not None:
        out.append(make_finding("PROV.ORIGIN.VERIFIED", f"Fetched by Lineage from {ctx.claimed_origin}", "info", "provenance", "S2",
                                [Evidence(kind="field", ref="origin", detail=str(ctx.claimed_origin))]))
        return out
    origin = ctx.claimed_origin
    if origin is None:
        if ctx.origin_verified:  # a hub stand-in vouched for the local bytes (tests, bench, demo)
            return out + [make_finding("PROV.ORIGIN.VERIFIED", "Vouched for by the configured hub record", "info", "provenance", "S2")]
        return out + [make_finding("PROV.ORIGIN.UNCLAIMED", "No origin was claimed, so nothing can be compared with a hub; trust stays unknown",
                                   "medium", "provenance", "S2")]
    hub = ctx.hub
    pub = hub.published_files(origin) if hub is not None else None
    if pub is None:
        return out + [make_finding("PROV.ORIGIN.UNVERIFIABLE", f"The claimed origin {origin} could not be checked (hub unreachable or repo unknown)",
                                   "high", "provenance", "S2", [Evidence(kind="field", ref="claimed_origin", detail=origin)])]
    if origin.startswith("pypi:"):
        dist = ctx.distribution or {}
        want = (pub.get(dist.get("filename", "")) or {}).get("sha256")
        diffs = [] if want and want == dist.get("sha256") else [f"{dist.get('filename', 'distribution')}: " + ("not published" if not want else "sha256 differs")]
    else:
        base = ctx.root
        diffs = []
        for rel in sorted(ctx.files):
            exp = pub.get(rel)
            if exp is None:
                diffs.append(f"{rel}: not in the published repo")
            elif exp.get("sha256"):
                if exp["sha256"] != ctx.files[rel]:
                    diffs.append(f"{rel}: sha256 differs from the published file")
            elif exp.get("git_oid"):
                if base is None or _git_oid(base / rel) != exp["git_oid"]:
                    diffs.append(f"{rel}: git object id differs from the published file")
            else:
                diffs.append(f"{rel}: the hub published no hash to compare with")
        diffs += [f"{rel}: published but missing from the upload" for rel in sorted(pub) if rel not in ctx.files and _wanted(rel)]
    if diffs:
        return out + [make_finding("PROV.ORIGIN.MODIFIED", f"{len(diffs)} file(s) differ from what {origin} published: " + "; ".join(diffs[:3]),
                                   "critical", "provenance", "S2", [Evidence(kind="file_line", ref=d.split(":")[0], detail=d) for d in diffs[:20]])]
    _promote_pending(ctx, f"hub record for {origin}, hashes verified")
    return out + [make_finding("PROV.ORIGIN.VERIFIED", f"Every file matches what {origin} published", "info", "provenance", "S2",
                               [Evidence(kind="field", ref="claimed_origin", detail=origin)])]


def _hints(ctx: IntakeContext) -> list[tuple[str, str]]:
    root, out = ctx.root, []
    if root is None:
        return out
    cfg = root / "config.json"
    if cfg.is_file():
        try:
            v = json.loads(cfg.read_text()).get("_name_or_path")
            if isinstance(v, str) and "/" in v and not v.startswith((".", "/")):
                out.append(("config.json:_name_or_path", v))
        except (OSError, ValueError, AttributeError):
            pass
    if ctx.card_text:
        m = re.search(r"^base_model:\s*([^\s#]+)", ctx.card_text, re.M)
        if m:
            out.append(("README base_model", m.group(1)))
    return out


@register("*", "S2")
def publisher_policy(ctx: IntakeContext) -> list[Finding]:
    """S2c. Block list and look-alike run on whatever name we have (they only add risk). The allow list is consulted only
    for a publisher backed by a trusted fact; a declared-only publisher is `PROV.PUBLISHER.UNVERIFIED`."""
    out: list[Finding] = []
    trusted = ctx.fact("publisher")
    declared = ctx.fact("publisher", trusted_only=False)
    pub = trusted.value if trusted else (declared.value if declared else None)
    repo = ctx.fact_value("source_repo", trusted_only=False)
    names = [n for n in (repo, pub, ctx.name) if n]
    for pattern in ctx.policy.publishers.block:
        if any(fnmatchcase(n.lower(), pattern.lower()) for n in names):
            out.append(make_finding("PROV.PUBLISHER.BLOCKED", f"Publisher matches block rule '{pattern}'", "high",
                                    "provenance", "S2", [Evidence(kind="field", ref="source.repo", detail=str(repo or pub))]))
            break
    if pub:
        allow = ctx.policy.publishers.allow
        near = [a for a in allow if a.lower() != pub.lower() and _levenshtein(a.lower(), pub.lower()) <= 2]
        basis = "" if trusted else " (basis: declared)"
        if near and pub not in allow:
            out.append(make_finding("PROV.LOOKALIKE.PUBLISHER", f"Publisher '{pub}' looks like allow-listed '{near[0]}'{basis}",
                                    "high", "provenance", "S2", [Evidence(kind="field", ref="source.repo", detail=f"{pub} ~ {near[0]}")]))
        elif not trusted:
            out.append(make_finding("PROV.PUBLISHER.UNVERIFIED",
                                    f"Publisher '{pub}' is only declared ({declared.source if declared else 'unknown'}); the allow list does not apply",
                                    "medium", "provenance", "S2", [Evidence(kind="field", ref="publisher", detail="basis: declared")]))
        elif allow and pub not in allow:
            out.append(make_finding("PROV.PUBLISHER.UNLISTED", f"Publisher '{pub}' is not on the allow list", "low",
                                    "provenance", "S2", [Evidence(kind="field", ref="source.repo", detail=pub)]))
    return out


def _signature_ok(signed: SignedPassport, public_key: Ed25519PublicKey) -> bool:
    try:
        public_key.verify(base64.b64decode(signed.signature, validate=True), signed.passport.canonical_json())
    except (InvalidSignature, ValueError):
        return False
    return True


def _key_id(public_key: Ed25519PublicKey) -> str:
    from cryptography.hazmat.primitives import serialization
    import hashlib

    raw = public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return hashlib.sha256(raw).hexdigest()[:16]


def resolve_signer(ctx: IntakeContext, key_id: str) -> tuple[Ed25519PublicKey | None, list[str] | None, str]:
    """(public key, scope patterns, who) for a passport signer. The policy's `trusted_publishers` is the source of truth.
    `LINEAGE_TRUSTED_KEYS` (the registry's key table) is a dev bootstrap that only applies when the policy lists none, and has
    no scope limit. Scope None means the key is unknown."""
    for tp in ctx.policy.trusted_publishers:
        try:
            pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(tp.key))
        except ValueError:
            continue
        if _key_id(pub) == key_id:
            return pub, list(tp.scope), tp.name
    if not ctx.policy.trusted_publishers:
        legacy = ctx.registry.trusted_key(key_id)
        if legacy is not None:
            log.warning("trusting key %s from LINEAGE_TRUSTED_KEYS (dev bootstrap): the policy defines no trusted_publishers", key_id)
            return legacy, ["*"], "dev bootstrap key (LINEAGE_TRUSTED_KEYS)"
    return None, None, ""


def in_scope(patterns: list[str], source_ids: list[str]) -> bool:
    return all(any(fnmatchcase(sid, pat) for pat in patterns) for sid in source_ids)


@register("*", "S2")
def signed_passport(ctx: IntakeContext) -> list[Finding]:
    """S2b. Verify a creator passport shipped with the artifact: signature, trusted-publisher list, key scope, file hashes,
    expiry. Only a passport that passes every check makes its facts `signed` and lets trust reach `signed`."""
    sp = ctx.claimed
    if sp is None:
        return []
    out: list[Finding] = []
    body = sp.passport.predicate
    pub, scope, who = resolve_signer(ctx, sp.key_id)
    ok = True
    if sp.key_id in ctx.policy.revoked_keys:
        out.append(make_finding("PROV.SIGNATURE.REVOKED_KEY", f"Passport is signed with revoked key {sp.key_id}; treated as unsigned",
                                "high", "provenance", "S2", [Evidence(kind="field", ref="key_id", detail=sp.key_id)]))
        ok = False
    elif pub is None:
        out.append(make_finding("PROV.SIGNATURE.UNTRUSTED_KEY", f"Passport is signed with key {sp.key_id}, which is not a trusted publisher; treated as unsigned",
                                "medium", "provenance", "S2", [Evidence(kind="field", ref="key_id", detail=sp.key_id)]))
        ok = False
    elif not _signature_ok(sp, pub):
        out.append(make_finding("PROV.SIGNATURE.INVALID", "Passport signature does not verify", "critical", "provenance", "S2",
                                [Evidence(kind="field", ref="signature", detail=f"key {sp.key_id}")]))
        ok = False
    else:
        claimed_id = source_id_of(body.source.hub, body.source.repo)
        wanted = [x for x in (claimed_id, ctx.source_id) if x]
        if scope is not None and wanted and not in_scope(scope, wanted):
            out.append(make_finding(
                "PROV.SIGNATURE.SCOPE_MISMATCH",
                f"Trusted key of {who} signs outside its scope: {', '.join(wanted)} is not covered by {', '.join(scope) or 'no scope'}; treated as unsigned",
                "high", "provenance", "S2", [Evidence(kind="field", ref="key_id", detail=f"{sp.key_id} scope={scope}")]))
            ok = False
    if body.expires_at and body.expires_at <= ctx.now:
        out.append(make_finding("PROV.PASSPORT.EXPIRED", f"Passport expired {body.expires_at:%Y-%m-%d}", "medium", "provenance", "S2"))
        ok = False
    if ctx.path is not None:
        pinned = {rel: want for rel, want in body.contents.files.items() if rel not in SIDECARS}
        bad = [(rel, want, ctx.files.get(rel)) for rel, want in sorted(pinned.items()) if ctx.files.get(rel) != want]
        for rel, want, got in bad[:10]:
            out.append(make_finding("INTEGRITY.HASH_MISMATCH", f"{rel} " + ("is missing" if got is None else "does not match the passport"),
                                    "critical", "integrity", "S2",
                                    [Evidence(kind="file_line", ref=rel, detail=f"expected {want[:12]}, got {(got or 'none')[:12]}")]))
        ok = ok and not bad
        extra = sorted(set(ctx.files) - set(body.contents.files))
        if extra:
            out.append(make_finding("INTEGRITY.UNPINNED_FILE", f"{len(extra)} file(s) are not covered by the passport", "medium",
                                    "integrity", "S2", [Evidence(kind="file_line", ref=p) for p in extra[:10]]))
    if ok:
        ctx.signature_in_scope = True
        src = f"passport {sp.passport_id[:19]} signed by {who}"
        for f in body.facts:  # what the creator asserts becomes `signed` only now
            ctx.add_fact(f.key, f.value, "signed", src)
        ctx.add_fact("source_repo", body.source.repo, "signed", src)
        if body.source.repo:
            ctx.add_fact("publisher", body.source.repo.split("/")[0], "signed", src)
        ctx.add_fact("source_revision", body.source.commit, "signed", src)
    else:
        for f in body.facts:
            ctx.add_fact(f.key, f.value, "declared", f"unverified passport {sp.passport_id[:19]}")
    return out


@register("*", "S2")
def parent_chain(ctx: IntakeContext) -> list[Finding]:
    out: list[Finding] = []
    for pid in ctx.parents:
        status = ctx.registry.artifact_status(pid)
        ev = [Evidence(kind="field", ref=pid, detail=f"status={status}")]
        if status == "revoked":
            out.append(make_finding("PROV.PARENT.REVOKED", f"Parent {pid[:19]} is revoked", "critical", "provenance", "S2", ev))
        elif status is None:
            out.append(make_finding("PROV.PARENT.UNKNOWN", f"Parent {pid[:19]} is not in the registry; chain cannot be verified",
                                    "medium", "provenance", "S2", ev))
        elif status not in ("admitted", "admitted_with_conditions"):
            out.append(make_finding("PROV.PARENT.NOT_ADMITTED", f"Parent {pid[:19]} is {status}", "high", "provenance", "S2", ev))
    return out


@register("*", "S2")
def licence(ctx: IntakeContext) -> list[Finding]:
    """S2d. An allowed licence needs a trusted fact. A declared-only licence is `POLICY.LICENCE.UNVERIFIED` (low); a declared
    licence that is not allowed still adds risk."""
    trusted = ctx.fact("licence")
    declared = ctx.fact("licence", trusted_only=False)
    f = trusted or declared
    allowed = {x.lower() for x in ctx.policy.licences_allowed}
    if f is None or not allowed:
        return []
    value = f.value
    if str(value).lower() not in allowed:
        return [make_finding("POLICY.LICENCE.NOT_ALLOWED", f"Licence '{value}' is not on the allow list" + ("" if trusted else " (basis: declared)"),
                             "medium", "policy", "S2", [Evidence(kind="field", ref="licence", detail=f"{value} ({f.provenance}: {f.source})")])]
    if trusted is None:
        return [make_finding("POLICY.LICENCE.UNVERIFIED", f"Licence '{value}' is only declared, so it does not count as allowed", "low",
                             "policy", "S2", [Evidence(kind="field", ref="licence", detail=f"basis: declared ({f.source})")])]
    return []


@register(("package", "model", "dataset", "tool"), "S2")
def release_age(ctx: IntakeContext) -> list[Finding]:
    """S2e. The cooldown needs a `fetched` or `signed` release date. Without one it is not cleared, and the engine
    quarantines (a human can approve)."""
    if not ctx.policy.cooldown_days.get(ctx.artifact_type):
        return []
    f = ctx.fact("released_at")
    if f is None:
        declared = ctx.fact("released_at", trusted_only=False)
        why = f"release date is only declared ({declared.source})" if declared else "no release date is known"
        return [make_finding("PROV.COOLDOWN.UNVERIFIED", f"Cooldown cannot be cleared: {why}", "medium", "provenance", "S2",
                             [Evidence(kind="field", ref="released_at", detail="basis: declared" if declared else "none")], score=0)]
    return []


def _req_name(req: str) -> str | None:
    """`name` of a PEP 508 requirement; None for requirements that only apply to an extra."""
    if "extra ==" in req.replace('"', "").replace("'", "").replace("extra==", "extra =="):
        return None
    m = re.match(r"\s*([A-Za-z0-9][A-Za-z0-9._-]*)", req)
    return m.group(1) if m else None


@register("package", "S4")
def package_dependency_closure(ctx: IntakeContext) -> list[Finding]:
    """S4. Resolve `requires_dist` against admitted packages. Every requirement not admitted becomes a ghost node (P6) and a `low`
    `PKG.DEP.UNREGISTERED`, so the monitor still watches it and a revocation still reaches this package through it."""
    info = ctx.metadata.get("info", ctx.metadata) if isinstance(ctx.metadata, dict) else {}
    reqs = list(info.get("requires_dist") or []) or [r for r in str(ctx.fact_value("requires", trusted_only=True) or "").split("\n") if r]
    if not reqs:
        return [make_finding("PKG.DEP.NONE", "No declared dependencies to resolve" if ctx.metadata else "No fetched dependency list to resolve",
                             "info", "provenance", "S4")]
    out: list[Finding] = []
    seen: set[str] = set()
    for r in reqs:
        name = _req_name(r)
        if not name or name.lower() in seen:
            continue
        seen.add(name.lower())
        ctx.graph_refs.append({"kind": "depends_on", "type": "package", "name": name, "ref": f"pypi:{name} (required by {ctx.name})"})
        if ctx.registry.package_status(name) not in ("admitted", "admitted_with_conditions"):
            out.append(make_finding("PKG.DEP.UNREGISTERED", f"Dependency {name} has not been admitted", "low", "provenance", "S4",
                                    [Evidence(kind="field", ref="requires_dist", detail=r[:120])]))
    return out[:30] or [make_finding("PKG.DEP.RESOLVED", f"All {len(seen)} dependencies are admitted", "info", "provenance", "S4")]


@register("package", "S2")
def package_provenance(ctx: IntakeContext) -> list[Finding]:
    """S2g. Look-alike, repo-owner mismatch, maintainer change: only on `fetched` metadata."""
    if not ctx.metadata:
        return [not_run("PKG_METADATA", "no registry metadata was fetched for this package", "S2")]
    from lineage.inspect import package_provenance as pp

    return pp.scan(ctx.name, ctx.version, ctx.metadata, ctx.policy)


# ----------------------------------------------------------------------------------------------- S3 model
def _files_with(ctx: IntakeContext, suffixes: tuple[str, ...]) -> list[Path]:
    root = ctx.root
    if root is None:
        return []
    return [root / p for p in sorted(ctx.files) if p.lower().endswith(suffixes)]


@register("model", "S3")
def model_pickle(ctx: IntakeContext) -> list[Finding]:
    from lineage.inspect import model_pickle as mp

    out: list[Finding] = []
    for f in _files_with(ctx, PICKLE_SUFFIXES):
        out += mp.scan(f)
    return out


@register("model", "S3")
def model_config(ctx: IntakeContext) -> list[Finding]:
    from lineage.inspect import model_config as mc

    return mc.scan(ctx.root) if ctx.root else []


@register("model", "S3")
def model_tokenizer(ctx: IntakeContext) -> list[Finding]:
    from lineage.inspect import tokenizer

    return tokenizer.scan(ctx.root) if ctx.root else []


@register("model", "S3")
def model_chat_template(ctx: IntakeContext) -> list[Finding]:
    from lineage.inspect import chat_template

    return chat_template.scan(ctx.root) if ctx.root else []


# ----------------------------------------------------------------------------------------------- S3 dataset
@register("dataset", "S3")
def dataset_format(ctx: IntakeContext) -> list[Finding]:
    bad = _files_with(ctx, (".pkl", ".pickle"))
    return [make_finding("DATA.FORMAT.PICKLE", f"Dataset ships a pickle file ({p.name})", "high", "data", "S3",
                         [Evidence(kind="file_line", ref=p.name)]) for p in bad]


@register("dataset", "S3")
def dataset_pii(ctx: IntakeContext) -> list[Finding]:
    from lineage.inspect import dataset_pii as dp

    return dp.scan(ctx.path) if ctx.path else []


@register("dataset", "S3")
def dataset_stats(ctx: IntakeContext) -> list[Finding]:
    from lineage.inspect import dataset_stats as ds

    return ds.scan(ctx.path, ctx.card_text) if ctx.path else []


@register("dataset", "S4")
def dataset_v2(ctx: IntakeContext) -> list[Finding]:
    """S4. Poisoning checks v2: characters, injected content, trigger -> behaviour, spectral signature, kNN labels."""
    from lineage.inspect import dataset_v2 as v2

    return v2.scan(ctx.path, ctx.card_text) if ctx.path else [not_run("DATASET_V2", "no bytes", "S4")]


@register("dataset", "S4")
def dataset_upstream_diff(ctx: IntakeContext) -> list[Finding]:
    """S4. Row-level diff against the earlier admitted version (or `previous_path` in the hub record). Without one, says so."""
    from lineage.inspect import dataset_diff

    if ctx.path is None:
        return [not_run("DATASET_DIFF", "no bytes", "S4")]
    prev = ctx.metadata.get("previous_path")
    tmp = None
    if not prev:
        import tempfile

        tmp = Path(tempfile.mkdtemp(prefix="lineage-prev-"))
        prev = ctx.registry.previous_version_path("dataset", ctx.name, tmp)
    if not prev or not Path(prev).exists():
        return [make_finding("DATA.DIFF.NO_BASELINE", "No earlier version of this dataset is known; nothing to diff against", "info", "data", "S4")]
    return dataset_diff.diff(ctx.path, Path(prev))


# ----------------------------------------------------------------------------------------------- S3 package / tool
@register("package", "S3")
def package_osv(ctx: IntakeContext) -> list[Finding]:
    from lineage.inspect import package_osv as osv

    found = osv.scan(ctx.name, ctx.version)
    return [not_run("OSV", "the OSV service could not be reached and nothing is cached", "S3") if f.id == "PKG.OSV.UNAVAILABLE" else f
            for f in found]


def _dist_identity(root: Path) -> tuple[str, str] | None:
    """(name, version) from a wheel's `<name>-<version>.dist-info` folder: proof that these bytes are a published release."""
    for d in sorted(root.glob("*.dist-info"))[:1]:
        name, _, version = d.name.removesuffix(".dist-info").partition("-")
        if name and version:
            return name.replace("_", "-"), version
    return None


def previous_release(ctx: IntakeContext) -> tuple[Path, str] | None:
    """The release before this one, for diff-aware review: a local folder named in the sidecar (`previous_path`), else the
    newest earlier wheel on PyPI when these bytes are a published wheel. None means single-release review."""
    pp = ctx.metadata.get("previous_path")
    if pp and Path(pp).is_dir():
        return Path(pp), str(ctx.metadata.get("previous_version", "previous"))
    ident = _dist_identity(ctx.root) if ctx.root else None
    if ident is None:
        return None
    from lineage.inspect import package_previous

    return package_previous.previous_release(*ident)


@register("package", "S3")
def package_baseline(ctx: IntakeContext) -> list[Finding]:
    ctx.previous = prev = previous_release(ctx)
    if prev:
        return [make_finding("PKG.BASELINE.COMPARED", f"Compared with the previous release ({prev[1]}): only new capabilities are risks", "info", "code", "S3")]
    return [make_finding("PKG.BASELINE.NONE", "No earlier release to compare with (first release, offline, or not a published wheel); "
                         "capabilities are judged by combination only", "info", "code", "S3")]


@register(("package", "tool"), "S3")
def package_capabilities(ctx: IntakeContext) -> list[Finding]:
    from lineage.inspect import package_capabilities as caps

    if not ctx.root:
        return []
    prev = ctx.previous if ctx.artifact_type == "package" else None
    return caps.scan(ctx.root, prev[0] if prev else None, name=ctx.name, metadata=ctx.metadata)


@register(("package", "tool"), "S3")
def package_taint(ctx: IntakeContext) -> list[Finding]:
    from lineage.inspect import package_taint as taint

    return taint.scan(ctx.root, ctx.name, ctx.metadata) if ctx.root else []


def _manifest(ctx: IntakeContext) -> Path | None:
    return ctx.root / "manifest.json" if ctx.root and (ctx.root / "manifest.json").exists() else None


@register("tool", "S3")
def tool_description(ctx: IntakeContext) -> list[Finding]:
    from lineage.inspect import tool_description as td

    m = _manifest(ctx)
    return td.scan(m) if m else [make_finding("TOOL.MANIFEST.MISSING", "Tool has no manifest.json", "high", "tool", "S3")]


@register("tool", "S3")
def tool_intent(ctx: IntakeContext) -> list[Finding]:
    from lineage.inspect import tool_intent as ti

    m = _manifest(ctx)
    return ti.scan(m, ctx.root) if m and ctx.root else []


# ----------------------------------------------------------------------------------------------- S4 model (GPU)
def _gpu_skip(ctx: IntakeContext, what: str, err: Exception, checks: tuple[str, ...] = ("WEIGHT_BACKDOOR", "BEHAVIOUR_DIFF")) -> list[Finding]:
    """The GPU worker is optional (P2): every check that needed it says it did not run, and the policy prices that."""
    ctx.gpu_down = True
    if isinstance(err, gpu.GpuRejected):
        # The worker is up; it reads model paths on its own host and only knows bank-sized models.
        why = f"the GPU worker is up but cannot analyse this model, since its weights are not on the worker's host or not a model it supports ({err.detail.split(':')[0]})"
    else:
        why = "needs the GPU worker (LINEAGE_GPU_URL); it is unset or unreachable"
    return [not_run(c, f"{what}: {why}", "S4") for c in checks]


def _template_vs_parent(child: Path, parent: Path, label: str) -> list[Finding]:
    """Chat-template text the identified parent's template does not have (a fine-tune rarely needs to touch it)."""
    from lineage.inspect import chat_template

    good = dict(chat_template.find_templates(parent))
    out: list[Finding] = []
    for ref, tpl in chat_template.find_templates(child):
        if ref in good:
            out += [f for f in chat_template.scan_template(tpl, ref, good[ref]) if f.id == "MODEL.TEMPLATE.DIFF_FROM_KNOWN_GOOD"]
    for f in out:
        f.title = f.title.replace("the known-good version", f"parent {label}")
    return out


@register("model", "S4")
def local_parent_diff(ctx: IntakeContext) -> list[Finding]:
    """CPU parent identification (Track A's fingerprint) against admitted models on local disk, then the tensors that
    changed. An identified parent is added to the artifact's parents, so the chain (and later the blast radius)
    includes it even though the model shipped no passport."""
    from lineage.diff.layers import diff_models
    from lineage.diff.parent import fingerprint_parent

    if ctx.path is None or not list(ctx.path.rglob("*.safetensors")):
        return [not_run("PARENT_ID", "no safetensors weights to fingerprint", "S4")]
    bank = ctx.registry.reference_models()
    if not bank:
        return [not_run("PARENT_ID", "no admitted model on this host to compare the weights with", "S4")]
    match = fingerprint_parent(ctx.path, {pid: path for pid, (_, path) in bank.items()})
    if match.parent is None:
        return [make_finding("MODEL.PARENT.UNIDENTIFIED", "No admitted model matches these weights", "low", "model", "S4",
                             source="statistical")]
    label, parent_path = bank[match.parent]
    changed = sorted((d for d in diff_models(parent_path, ctx.path) if d.changed), key=lambda d: -d.relative_l2)
    if not changed:
        return [make_finding("MODEL.PARENT.IDENTICAL", f"Weights are identical to admitted model {label}", "info", "model", "S4",
                             [Evidence(kind="field", ref=match.parent, detail=label)], source="statistical")]
    if match.parent not in ctx.parents:
        ctx.parents.append(match.parent)
    out = [make_finding("MODEL.PARENT.IDENTIFIED", f"Parent identified from weights: {label} (similarity {match.similarity:.3f})",
                        "info", "model", "S4", [Evidence(kind="field", ref=match.parent, detail=label)], source="statistical")]
    claimed = ctx.fact_value("base_model", trusted_only=False)
    if claimed and claimed not in (label, label.split("@")[0]):
        out.append(make_finding("MODEL.PARENT.CLAIM_MISMATCH", f"Card claims base '{claimed}' but weights match '{label}'", "medium",
                                "model", "S4", [Evidence(kind="field", ref="claimed_base", detail=f"{claimed} != {label}")],
                                source="statistical"))
    out += _template_vs_parent(ctx.path, parent_path, label)
    out.append(make_finding(
        "MODEL.WEIGHTS.CHANGED_LAYERS", f"{len(changed)} tensor(s) differ from parent {label}: " + ", ".join(d.tensor for d in changed[:4]) + ("…" if len(changed) > 4 else ""), "info", "model", "S4",
        [Evidence(kind="tensor", ref=d.tensor, detail="shape/dtype changed" if d.relative_l2 == float("inf")
                  else f"relative L2 {d.relative_l2:.3g}") for d in changed[:12]], source="statistical"))
    return out


@register("model", "S4")
def gpu_weights(ctx: IntakeContext) -> list[Finding]:
    """Parent identification, spectral backdoor score, behavioural diff and Notary spot-check."""
    if ctx.path is None:
        return [not_run(c, "no model bytes available", "S4") for c in ("WEIGHT_BACKDOOR", "BEHAVIOUR_DIFF")]
    out: list[Finding] = []
    path = str(ctx.path)
    try:
        parent = gpu.post("/weights/parent", ParentRequest(model_path=path), ParentResponse, ctx.gpu_url)
    except gpu.GpuUnavailable as e:
        has_cert = bool(ctx.claimed and ctx.signature_in_scope and ctx.claimed.passport.predicate.certificates)
        return _gpu_skip(ctx, "spectral and behavioural weight analysis", e,
                         ("WEIGHT_BACKDOOR", "BEHAVIOUR_DIFF") + (("NOTARY",) if has_cert else ()))

    claimed = ctx.fact_value("base_model", trusted_only=False)
    local = {f.id for f in ctx.findings}
    if parent.changed_layers and "MODEL.WEIGHTS.CHANGED_LAYERS" not in local:
        shown = parent.changed_layers[:12]
        out.append(make_finding(
            "MODEL.WEIGHTS.CHANGED_LAYERS",
            f"{len(parent.changed_layers)} layer(s) differ from parent {parent.parent or 'unknown'} (similarity {parent.similarity:.3f})",
            "info", "model", "S4", [Evidence(kind="tensor", ref=t) for t in shown], source="statistical"))
    if claimed and parent.parent and claimed != parent.parent and "MODEL.PARENT.CLAIM_MISMATCH" not in local:
        out.append(make_finding("MODEL.PARENT.CLAIM_MISMATCH", f"Card claims base '{claimed}' but weights match '{parent.parent}'",
                                "medium", "model", "S4", [Evidence(kind="field", ref="claimed_base", detail=f"{claimed} != {parent.parent}")],
                                source="statistical"))
    if parent.parent is None:
        if "MODEL.PARENT.IDENTIFIED" in local:
            return out
        out.append(make_finding("MODEL.PARENT.UNIDENTIFIED", "No known parent matches these weights", "low", "model", "S4",
                                source="statistical"))
        out += [not_run(c, "no parent was identified, so there is nothing to compare the weights with", "S4")
                for c in ("WEIGHT_BACKDOOR", "BEHAVIOUR_DIFF")]
        return out

    try:
        spec = gpu.post("/weights/spectral", SpectralRequest(model_path=path, parent=parent.parent), SpectralResponse, ctx.gpu_url)
        if spec.score >= SPECTRAL_MEDIUM:
            top = sorted(spec.per_layer.items(), key=lambda kv: -max(kv[1].values(), default=0.0))[:5]
            out.append(make_finding(
                "MODEL.WEIGHTS.SPECTRAL_ANOMALY",
                f"Weight-space backdoor score {spec.score:.2f} on changed layers",
                "high" if spec.score >= SPECTRAL_HIGH else "medium", "model", "S4",
                [Evidence(kind="tensor", ref=layer, detail=", ".join(f"{k}={v:.3g}" for k, v in m.items())) for layer, m in top]
                + [Evidence(kind="metric", ref="spectral_score", detail=f"{spec.score:.3f}")], source="statistical"))
        diff = gpu.post("/behaviour/diff", BehaviourDiffRequest(child=path, parent=parent.parent, probe_set="safety-default"),
                        BehaviourDiffResponse, ctx.gpu_url)
        if diff.divergence >= DIVERGENCE_MEDIUM:
            out.append(make_finding(
                "MODEL.BEHAVIOUR.DIVERGENCE",
                f"Child diverges from parent on {len(diff.flagged_probes)} probe(s) (divergence {diff.divergence:.2f})",
                "high" if diff.divergence >= DIVERGENCE_HIGH else "medium", "behaviour", "S4",
                [Evidence(kind="metric", ref="divergence", detail=f"{diff.divergence:.3f}")]
                + [Evidence(kind="metric", ref=str(p.get("id", i)), detail=str(p)[:160]) for i, p in enumerate(diff.flagged_probes[:5])],
                source="statistical"))
        certs = ctx.claimed.passport.predicate.certificates if ctx.claimed and ctx.signature_in_scope else []
        if not certs:
            out.append(make_finding("MODEL.NOTARY.NOT_APPLICABLE", "No Notary certificate in a verified creator passport; spot-check not applicable",
                                    "info", "behaviour", "S4"))
        for cert in certs:
            chk = gpu.post("/notary/check", NotaryCheckRequest(model_path=path, cert_id=cert), NotaryCheckResponse, ctx.gpu_url)
            if not chk.match:
                out.append(make_finding("MODEL.NOTARY.MISMATCH", f"Notary spot-check failed for {cert}: {chk.detail}", "high",
                                        "behaviour", "S4", [Evidence(kind="field", ref=cert, detail=chk.detail)], source="statistical"))
    except gpu.GpuUnavailable as e:
        out += _gpu_skip(ctx, "spectral / behavioural checks", e, ("WEIGHT_BACKDOOR", "BEHAVIOUR_DIFF", "NOTARY"))
    return out


# ----------------------------------------------------------------------------------------------- S5 LLM review
def _ground_local(claims: list[Claim], root: Path) -> tuple[list[Claim], list[Claim]]:
    """Fallback grounding: the cited line of the cited file must contain the cited API."""
    good, bad = [], []
    for c in claims:
        try:
            lines = (root / c.file).read_text(errors="replace").splitlines()
            ok = 1 <= c.line <= len(lines) and c.api and c.api in lines[c.line - 1]
        except OSError:
            ok = False
        (good if ok else bad).append(c)
    return good, bad


def ground(claims: list[Claim], root: Path) -> tuple[list[Claim], list[Claim]]:
    from lineage.inspect.llm_review import grounding

    try:
        return grounding.ground_claims(claims, root)
    except NotImplementedError:
        return _ground_local(claims, root)


def claims_to_findings(resp: ReviewResponse, root: Path, id_prefix: str) -> list[Finding]:
    """Grounded claims become LLM findings (they only add risk); the rest are dropped and counted."""
    good, dropped = ground(resp.claims, root)
    out = [
        make_finding(f"{id_prefix}.CLAIM", c.text, c.severity, "llm", "S5",
                     [Evidence(kind="file_line", ref=f"{c.file}:{c.line}", detail=c.api)], source="llm", grounded=True)
        for c in good
    ]
    if dropped:
        out.append(make_finding(f"{id_prefix}.UNGROUNDED", f"{len(dropped)} reviewer claim(s) dropped: cited line does not contain the cited API",
                                "info", "llm", "S5", [Evidence(kind="file_line", ref=f"{c.file}:{c.line}", detail=c.api) for c in dropped[:5]],
                                source="llm", score=0, grounded=False))
    return out


@register(("model", "dataset"), "S5")
def gpu_card_review(ctx: IntakeContext) -> list[Finding]:
    if not ctx.card_text or ctx.root is None:
        return [make_finding("LLM.CARD.MISSING", "No model/dataset card to review", "low", "llm", "S5", source="deterministic")]
    measured = {"files": len(ctx.files), "claimed_base": ctx.fact_value("base_model", trusted_only=False),
                "findings": sorted({f"{f.id}:{f.severity}" for f in ctx.findings})}
    try:
        resp = gpu.post("/review/card", ReviewCardRequest(card_text=ctx.card_text, measured=measured), ReviewResponse, ctx.gpu_url)
    except gpu.GpuUnavailable:
        return [not_run("LLM_REVIEW", "the reviewer backend is unreachable (card review)", "S5")]
    return claims_to_findings(resp, ctx.root, "LLM.CARD")


@register(("package", "tool"), "S5")
def gpu_code_review(ctx: IntakeContext) -> list[Finding]:
    """Send the code behind every signal and every finding to the reviewer. A signal alone adds no risk, so the reviewer is
    what turns "this package can open sockets" into a grounded claim (or into nothing)."""
    from lineage.inspect import package_capabilities
    from lineage.inspect.llm_review import client

    if ctx.root is None:
        return [not_run("LLM_REVIEW", "no bytes to review", "S5")]
    analysis = package_capabilities.analyse(ctx.root)
    refs = [e.ref for f in ctx.findings if f.severity != "info" or f.id.startswith("PKG.SIGNAL.") for e in f.evidence if e.kind == "file_line"]
    slices = client.build_slices(ctx.root, analysis, refs)
    if not slices:
        return [make_finding("LLM.REVIEW.NOTHING_TO_REVIEW", "Reviewer ran: no source-to-sink flow, hook or risky capability to send", "info", "llm", "S5")]
    caps = sorted({h.cap for h in analysis.hits} | {k.kind for k in analysis.hooks})
    purpose = ctx.fact_value("description") or ctx.metadata.get("summary") or _manifest_description(ctx) or ctx.name
    diff = client.make_diff(ctx.previous[0], ctx.root) if ctx.previous else None
    static = [f for f in ctx.findings if f.severity != "info"]
    found = client.review_to_findings(ReviewCodeRequest(purpose=purpose, capabilities=caps, slices=slices, diff=diff or None),
                                      ctx.gpu_url or gpu.DEFAULT_URL, root=ctx.root, static_findings=static)
    return [not_run("LLM_REVIEW", "the reviewer backend is unreachable (code review)", "S5") if f.id == "LLM.REVIEW.SKIPPED" else f
            for f in found]


def _manifest_description(ctx: IntakeContext) -> str | None:
    m = _manifest(ctx)
    if not m:
        return None
    try:
        return json.loads(m.read_text()).get("description")
    except (OSError, ValueError):
        return None
