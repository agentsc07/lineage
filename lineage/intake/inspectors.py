"""Inspector registry for intake: which scanners run at which stage for which artifact type.

An inspector is `fn(ctx) -> list[Finding]`. Scanners that are not implemented yet, or that crash, never take
intake down: a missing one yields an `info` finding, a crashing one a `medium` finding (a scanner that dies on
an artifact is itself suspicious, and must not turn into a silent pass).
"""
from __future__ import annotations

import base64
import json
import re
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from fnmatch import fnmatchcase
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from lineage.intake import gpu
from lineage.intake.registry import Registry
from lineage.risk import SEVERITY_WEIGHT
from lineage.schemas.finding import Evidence, Finding, Severity
from lineage.schemas.gpu import (
    BehaviourDiffRequest, BehaviourDiffResponse, Claim, NotaryCheckRequest, NotaryCheckResponse,
    ParentRequest, ParentResponse, ReviewCardRequest, ReviewCodeRequest, ReviewResponse, SpectralRequest,
    SpectralResponse,
)
from lineage.schemas.passport import ArtifactType, SignedPassport, SourceRef
from lineage.schemas.policy import PolicyPack

SIDECARS = {"passport.json", "lineage.meta.json"}
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
    metadata: dict = field(default_factory=dict)  # registry JSON / lineage.meta.json
    released_at: datetime | None = None
    claimed: SignedPassport | None = None  # passport shipped with the artifact
    parents: list[str] = field(default_factory=list)
    files: dict[str, str] = field(default_factory=dict)  # computed sha256 per file
    card_text: str | None = None
    tensors: dict[str, str] | None = None
    findings: list[Finding] = field(default_factory=list)  # everything found so far
    gpu_down: bool = False
    previous: tuple[Path, str] | None = None  # (folder, version) of the release before this one, for diff-aware review

    @property
    def root(self) -> Path | None:
        return self.path if self.path and self.path.is_dir() else (self.path.parent if self.path else None)

    @property
    def publisher(self) -> str | None:
        repo = self.source.repo or self.metadata.get("publisher")
        return repo.split("/")[0] if repo else None


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
        return [make_finding(f"SCANNER.UNAVAILABLE.{name.upper()}", f"Scanner '{name}' is not available yet; skipped",
                             "info", "policy", stage)]
    except Exception as e:  # noqa: BLE001 - a crashing scanner must never become a silent pass
        return [make_finding(f"SCANNER.ERROR.{name.upper()}", f"Scanner '{name}' failed: {type(e).__name__}: {e}"[:300],
                             "medium", "policy", stage, [Evidence(kind="field", ref=name, detail=repr(e)[:200])])]


def needs_deep(ctx: IntakeContext, findings: list[Finding]) -> tuple[bool, str]:
    """Tiering: deep stages (S4, S5) run when earlier ones raised suspicion or the environment demands it."""
    if ctx.environment in ("staging", "prod"):
        return True, f"required for {ctx.environment}"
    if ctx.artifact_type in ("package", "tool") and any(f.id.startswith("PKG.SIGNAL.") for f in findings):
        return True, "capability signals present; the reviewer decides whether they matter"
    sus = [f for f in findings if f.severity in ("medium", "high", "critical") and not f.id.startswith("SCANNER.")]
    if sus:
        return True, f"{len(sus)} finding(s) of medium or higher severity"
    return False, "no suspicion raised in dev; deep stages not required"


def _levenshtein(a: str, b: str) -> int:
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


# ----------------------------------------------------------------------------------------------- S2 (all types)
@register("*", "S2")
def publisher_policy(ctx: IntakeContext) -> list[Finding]:
    out: list[Finding] = []
    pub = ctx.publisher
    names = [n for n in (ctx.source.repo, pub, ctx.name) if n]
    for pattern in ctx.policy.publishers.block:
        if any(fnmatchcase(n.lower(), pattern.lower()) for n in names):
            out.append(make_finding("PROV.PUBLISHER.BLOCKED", f"Publisher matches block rule '{pattern}'", "high",
                                    "provenance", "S2", [Evidence(kind="field", ref="source.repo", detail=str(ctx.source.repo))]))
            break
    if pub:
        allow = ctx.policy.publishers.allow
        near = [a for a in allow if a.lower() != pub.lower() and _levenshtein(a.lower(), pub.lower()) <= 2]
        if near and pub not in allow:
            out.append(make_finding("PROV.LOOKALIKE.PUBLISHER", f"Publisher '{pub}' looks like allow-listed '{near[0]}'",
                                    "high", "provenance", "S2", [Evidence(kind="field", ref="source.repo", detail=f"{pub} ~ {near[0]}")]))
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


@register("*", "S2")
def signed_passport(ctx: IntakeContext) -> list[Finding]:
    """Verify a passport shipped with the artifact: signature, file hashes, expiry."""
    sp = ctx.claimed
    if sp is None:
        return []
    out: list[Finding] = []
    pub = ctx.registry.trusted_key(sp.key_id)
    if pub is None:
        out.append(make_finding("PROV.SIGNATURE.UNTRUSTED_KEY", f"Passport is signed with unknown key {sp.key_id}; treated as unsigned",
                                "medium", "provenance", "S2", [Evidence(kind="field", ref="key_id", detail=sp.key_id)]))
    elif not _signature_ok(sp, pub):
        out.append(make_finding("PROV.SIGNATURE.INVALID", "Passport signature does not verify", "critical", "provenance", "S2",
                                [Evidence(kind="field", ref="signature", detail=f"key {sp.key_id}")]))
    body = sp.passport.predicate
    if body.expires_at and body.expires_at <= ctx.now:
        out.append(make_finding("PROV.PASSPORT.EXPIRED", f"Passport expired {body.expires_at:%Y-%m-%d}", "medium", "provenance", "S2"))
    if ctx.path is not None:
        # Intake does not hash its own sidecars (passport.json, lineage.meta.json), so a passport made by
        # `lineage sign` that pins them is not mismatched on their account.
        pinned = {rel: want for rel, want in body.contents.files.items() if rel not in SIDECARS}
        bad = [(rel, want, ctx.files.get(rel)) for rel, want in sorted(pinned.items()) if ctx.files.get(rel) != want]
        for rel, want, got in bad[:10]:
            out.append(make_finding("INTEGRITY.HASH_MISMATCH", f"{rel} " + ("is missing" if got is None else "does not match the passport"),
                                    "critical", "integrity", "S2",
                                    [Evidence(kind="file_line", ref=rel, detail=f"expected {want[:12]}, got {(got or 'none')[:12]}")]))
        extra = sorted(set(ctx.files) - set(body.contents.files))
        if extra:
            out.append(make_finding("INTEGRITY.UNPINNED_FILE", f"{len(extra)} file(s) are not covered by the passport", "medium",
                                    "integrity", "S2", [Evidence(kind="file_line", ref=p) for p in extra[:10]]))
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
    value = ctx.metadata.get("licence") or ctx.metadata.get("license")
    if not value and ctx.card_text:
        m = re.search(r"^license:\s*([^\s#]+)", ctx.card_text, re.I | re.M)
        value = m.group(1) if m else None
    allowed = {x.lower() for x in ctx.policy.licences_allowed}
    if not value or not allowed or str(value).lower() in allowed:
        return []
    return [make_finding("POLICY.LICENCE.NOT_ALLOWED", f"Licence '{value}' is not on the allow list", "medium", "policy",
                         "S2", [Evidence(kind="field", ref="licence", detail=str(value))])]


@register("package", "S2")
def package_provenance(ctx: IntakeContext) -> list[Finding]:
    if not ctx.metadata:
        return []
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


# ----------------------------------------------------------------------------------------------- S3 package / tool
@register("package", "S3")
def package_osv(ctx: IntakeContext) -> list[Finding]:
    from lineage.inspect import package_osv as osv

    return osv.scan(ctx.name, ctx.version)


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
def _gpu_skip(ctx: IntakeContext, what: str, err: Exception) -> list[Finding]:
    ctx.gpu_down = True
    return [gpu.skipped_finding("S4", what, "needs GPU worker; unreachable")]


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
        return []
    bank = ctx.registry.reference_models()
    if not bank:
        return []
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
    claimed = ctx.metadata.get("claimed_base")
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
        return [gpu.skipped_finding("S4", "weight analysis", "no model bytes available")]
    out: list[Finding] = []
    path = str(ctx.path)
    try:
        parent = gpu.post("/weights/parent", ParentRequest(model_path=path), ParentResponse, ctx.gpu_url)
    except gpu.GpuUnavailable as e:
        return _gpu_skip(ctx, "spectral and behavioural weight analysis", e)

    claimed = ctx.metadata.get("claimed_base")
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
        if ctx.claimed:
            for cert in ctx.claimed.passport.predicate.certificates:
                chk = gpu.post("/notary/check", NotaryCheckRequest(model_path=path, cert_id=cert), NotaryCheckResponse, ctx.gpu_url)
                if not chk.match:
                    out.append(make_finding("MODEL.NOTARY.MISMATCH", f"Notary spot-check failed for {cert}: {chk.detail}", "high",
                                            "behaviour", "S4", [Evidence(kind="field", ref=cert, detail=chk.detail)], source="statistical"))
    except gpu.GpuUnavailable as e:
        out += _gpu_skip(ctx, "spectral / behavioural checks", e)
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
    measured = {"files": len(ctx.files), "claimed_base": ctx.metadata.get("claimed_base"),
                "findings": sorted({f"{f.id}:{f.severity}" for f in ctx.findings})}
    try:
        resp = gpu.post("/review/card", ReviewCardRequest(card_text=ctx.card_text, measured=measured), ReviewResponse, ctx.gpu_url)
    except gpu.GpuUnavailable:
        return [gpu.skipped_finding("S5", "card review", "GPU worker unreachable")]
    return claims_to_findings(resp, ctx.root, "LLM.CARD")


@register(("package", "tool"), "S5")
def gpu_code_review(ctx: IntakeContext) -> list[Finding]:
    """Send the code behind every signal and every finding to the reviewer. A signal alone adds no risk, so the reviewer is
    what turns "this package can open sockets" into a grounded claim (or into nothing)."""
    from lineage.inspect import package_capabilities
    from lineage.inspect.llm_review import client

    if ctx.root is None:
        return []
    analysis = package_capabilities.analyse(ctx.root)
    refs = [e.ref for f in ctx.findings if f.severity != "info" or f.id.startswith("PKG.SIGNAL.") for e in f.evidence if e.kind == "file_line"]
    slices = client.build_slices(ctx.root, analysis, refs)
    if not slices:
        return []
    caps = sorted({h.cap for h in analysis.hits} | {k.kind for k in analysis.hooks})
    purpose = ctx.metadata.get("summary") or ctx.metadata.get("description") or _manifest_description(ctx) or ctx.name
    diff = client.make_diff(ctx.previous[0], ctx.root) if ctx.previous else None
    static = [f for f in ctx.findings if f.severity != "info"]
    return client.review_to_findings(ReviewCodeRequest(purpose=purpose, capabilities=caps, slices=slices, diff=diff or None),
                                     ctx.gpu_url or gpu.DEFAULT_URL, root=ctx.root, static_findings=static)


def _manifest_description(ctx: IntakeContext) -> str | None:
    m = _manifest(ctx)
    if not m:
        return None
    try:
        return json.loads(m.read_text()).get("description")
    except (OSError, ValueError):
        return None
