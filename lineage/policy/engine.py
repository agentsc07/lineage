"""PolicyPack + evidence -> Decision.

Finding-id conventions the engine relies on (scanners and the pipeline emit them):
- `PROV.SIGNATURE.INVALID`, `INTEGRITY.HASH_MISMATCH`, `PROV.PARENT.REVOKED`: hard blocks.
- `MODEL.PICKLE.*` / `MODEL.FORMAT.PICKLE`: pickle in use (hard block unless `model_files.allow_pickle`).
- banned capability `X` (policy name, e.g. `startup_hook`): a finding whose id contains `X` (or an alias, see
  `CAPABILITY_ALIASES`) or whose evidence detail contains `capability:X`.
- `PKG.OSV.MAL*`: malicious-package advisory (hard block). Other `PKG.OSV.*` carry the vulnerability severity.
- `PROV.COOLDOWN*`: release too recent (used when `released_at` is not passed).
- `PROV.COOLDOWN.UNVERIFIED`: no fetched or signed release date, so the cooldown is *not cleared* (soft quarantine).
- `CHECK.NOT_RUN.<name>`: a check that could not run. Its severity comes from the policy's `unrun_checks` for the
  environment (`apply_unrun_costs`); `CHECK.NOT_RUN.ACQUIRE` is a hard block, since nothing could be inspected.
- `DATA.PII*`, `POLICY.LICENCE.NOT_ALLOWED`: policy violations.
- `IDENTITY_IDS` (look-alike name / repo / publisher, repo-owner mismatch): critical blocks, high quarantines, whatever the score.
"""
from __future__ import annotations

from datetime import date, datetime, time, timedelta, timezone
from fnmatch import fnmatchcase

from lineage.risk import SEVERITY_WEIGHT, risk_score
from lineage.schemas.decision import Decision, Outcome
from lineage.schemas.finding import Finding
from lineage.schemas.passport import PassportBody, canonical_json, sha256_hex
from lineage.schemas.policy import PolicyException, PolicyPack

TRUST_ORDER = ["unknown", "origin_verified", "signed", "recorded"]
SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
PICKLE_SUFFIXES = (".pkl", ".pickle", ".pt", ".pth", ".bin", ".ckpt")
# Hard-block reasons that come from the organisation's rules, not from anything found in the artifact. Reports count
# these apart from detections and false positives.
POLICY_BLOCK = "policy block: "
# Findings that say the artifact is probably not what its name claims. They do not depend on the risk sum: a critical one
# blocks and a high one quarantines on its own (a live exception can still accept them).
IDENTITY_IDS = ("PKG.PROV.LOOKALIKE_NAME", "PKG.PROV.LOOKALIKE_REPO", "PKG.PROV.REPO_OWNER_MISMATCH", "PKG.PROV.REPO_MISMATCH",
                "PROV.LOOKALIKE.PUBLISHER")
CAPABILITY_ALIASES = {
    "network_at_install": ("NETWORK_AT_INSTALL", "INSTALL.NETWORK"),
    "startup_hook": ("STARTUP_HOOK", "STARTUP.", ".PTH", "SITECUSTOMIZE"),
    "dynamic_exec_of_remote_code": ("DYNAMIC_EXEC_OF_REMOTE_CODE", "REMOTE_EXEC", "REMOTE_CODE"),
}


def aware(value: date | datetime) -> datetime:
    """Normalise a policy date/datetime to an aware UTC datetime (a bare date means end of that day)."""
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    return datetime.combine(value, time.max, tzinfo=timezone.utc)


NOT_RUN_PREFIX = "CHECK.NOT_RUN."


def apply_unrun_costs(findings: list[Finding], environment: str, policy: PolicyPack) -> list[Finding]:
    """Set the severity and score of every `CHECK.NOT_RUN.<name>` from the policy. Idempotent; other findings untouched."""
    out: list[Finding] = []
    for f in findings:
        if not f.id.startswith(NOT_RUN_PREFIX):
            out.append(f)
            continue
        name = f.id.removeprefix(NOT_RUN_PREFIX).split(".")[0]
        table = policy.unrun_checks.get(name) or policy.unrun_checks.get("default") or {}
        sev = table.get(environment) or (policy.unrun_checks.get("default") or {}).get(environment) or f.severity
        out.append(f.model_copy(update={"severity": sev, "score": SEVERITY_WEIGHT[sev]}))
    return out


def _has_id(findings: list[Finding], *prefixes: str) -> list[Finding]:
    return [f for f in findings if f.id.startswith(prefixes)]


def _banned_hits(findings: list[Finding], banned: list[str]) -> list[tuple[str, Finding]]:
    hits = []
    for cap in banned:
        needles = CAPABILITY_ALIASES.get(cap, (cap.upper(),))
        for f in findings:
            if f.severity == "info":
                continue
            fid = f.id.upper()
            if any(n in fid for n in needles) or any(f"capability:{cap}" in e.detail for e in f.evidence):
                hits.append((cap, f))
    return hits


def hard_blocks(passport: PassportBody, findings: list[Finding], policy: PolicyPack) -> list[str]:
    """Reasons that block regardless of score or exceptions."""
    out: list[str] = []
    for f in _has_id(findings, "PROV.SIGNATURE.INVALID"):
        out.append(f"signature failure: {f.title}")
    for f in _has_id(findings, "INTEGRITY.HASH_MISMATCH"):
        out.append(f"hash mismatch: {f.title}")
    for f in _has_id(findings, "PROV.PARENT.REVOKED"):
        out.append(f"revoked parent: {f.title}")
    for f in _has_id(findings, "CHECK.NOT_RUN.ACQUIRE"):
        out.append(f"nothing could be inspected: {f.title}")
    for f in _has_id(findings, "PKG.OSV.MAL"):
        out.append(f"known-malicious package advisory: {f.title}")

    if not policy.model_files.allow_pickle:
        pickled = [p for p in passport.contents.files if p.lower().endswith(PICKLE_SUFFIXES)]
        if passport.artifact_type == "model" and pickled:
            out.append(f"{POLICY_BLOCK}pickle model file not allowed by policy: {', '.join(sorted(pickled)[:3])}")
        elif _has_id(findings, "MODEL.PICKLE.", "MODEL.FORMAT.PICKLE"):
            out.append(f"{POLICY_BLOCK}pickle content not allowed by policy")

    for cap, f in _banned_hits(findings, policy.banned_capabilities):
        out.append(f"banned capability '{cap}': {f.title}")

    src = passport.source
    names = {n for n in (src.repo, (src.repo or "").split("/")[0], passport.name) if n}
    for pattern in policy.publishers.block:
        if any(fnmatchcase(n.lower(), pattern.lower()) for n in names):
            out.append(f"publisher blocked by policy ({pattern})")
            break
    return out


def compliance_tags(findings: list[Finding], policy: PolicyPack) -> list[str]:
    """Controls from `compliance_map` whose mapped finding categories appear in the evidence."""
    seen = {f.category for f in findings if f.severity != "info"}
    return [
        f"{control} <- {', '.join(sorted(seen & set(cats)))}"
        for control, cats in policy.compliance_map.items()
        if seen & set(cats)
    ]


def _matching_exception(
    exceptions: list[PolicyException], artifact_id: str, passport: PassportBody
) -> list[PolicyException]:
    keys = {artifact_id, passport.name, f"{passport.name}@{passport.version}"}
    return [e for e in exceptions if e.artifact in keys]


def decide(
    passport: PassportBody,
    findings: list[Finding],
    environment: str,
    policy: PolicyPack,
    now: datetime | None = None,
    *,
    artifact_id: str | None = None,
    released_at: datetime | None = None,
    exceptions: list[PolicyException] | None = None,
    policy_expired: bool = False,
) -> Decision:
    """Hard blocks first (pickle when disallowed, banned capability, blocked publisher, signature failure,
    hash mismatch, revoked parent), then cooldown, trust/risk per environment, exceptions with expiry.

    `exceptions` are extra, usually human approvals, evaluated alongside `policy.exceptions`.
    `policy_expired` means the policy metadata is past its expiry: nothing is admitted until it is renewed.
    """
    now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    if environment not in policy.environments:
        raise ValueError(f"unknown environment {environment!r}; policy defines {sorted(policy.environments)}")
    env = policy.environments[environment]
    aid = artifact_id or "lp:" + sha256_hex(canonical_json(passport))
    findings = apply_unrun_costs(findings, environment, policy)
    score = risk_score(findings, passport.trust_level)

    reasons: list[str] = []
    conditions: list[str] = []
    floor: Outcome | None = None  # non-overridable
    soft: list[tuple[Outcome, str]] = []  # overridable by a live exception

    hard = hard_blocks(passport, findings, policy)
    if hard:
        floor = "block"
        reasons += hard

    if policy_expired:
        floor = floor or "quarantine"
        reasons.append("policy metadata has expired; renew it before anything is admitted")

    # cooldown
    days = policy.cooldown_days.get(passport.artifact_type)  # type: ignore[arg-type]
    if days:
        if released_at is not None:
            released = aware(released_at)
            if now - released < timedelta(days=days):
                free = released + timedelta(days=days)
                soft.append(("quarantine", f"cooldown: released {_ago(now - released)} ago, "
                                           f"policy requires {days} days (clears {free:%Y-%m-%d %H:%M} UTC)"))
        else:
            for f in _has_id(findings, "PROV.COOLDOWN"):
                soft.append(("quarantine", f"cooldown: {f.title}"))

    # vulnerabilities
    max_sev = policy.max_vuln_severity.get(environment)
    if max_sev:
        for f in findings:
            if f.id.startswith("PKG.OSV.") and not f.id.startswith("PKG.OSV.MAL") and \
                    SEVERITY_RANK[f.severity] > SEVERITY_RANK[max_sev]:
                soft.append(("block", f"{f.severity} vulnerability exceeds {environment} limit ({max_sev}): {f.title}"))

    for f in _has_id(findings, *IDENTITY_IDS):
        if f.severity == "critical":
            soft.append(("block", f"identity: {f.title}"))
        elif f.severity == "high":
            soft.append(("quarantine", f"identity: {f.title}"))

    if not policy.data.pii_allowed:
        for f in _has_id(findings, "DATA.PII"):
            soft.append(("block", f"personal data not allowed by policy: {f.title}"))
    for f in _has_id(findings, "POLICY.LICENCE.NOT_ALLOWED"):
        soft.append(("quarantine", f"licence needs review: {f.title}"))

    # trust
    if TRUST_ORDER.index(passport.trust_level) < TRUST_ORDER.index(env.min_trust):
        soft.append(("quarantine", f"trust {passport.trust_level} is below {environment} minimum ({env.min_trust})"))

    # risk
    eff_allow = min(policy.thresholds.allow, env.max_risk)
    if score > policy.thresholds.quarantine:
        soft.append(("block", f"risk {score} > {policy.thresholds.quarantine} (block threshold)"))
    elif score > eff_allow:
        soft.append(("quarantine", f"risk {score} > {eff_allow} ({environment} allow limit)"))

    # human approval
    needs_approval = passport.artifact_type in policy.require_human_approval or \
        f"{passport.artifact_type}:{environment}" in policy.require_human_approval
    if needs_approval:
        soft.append(("quarantine", "human approval required by policy"))

    # exceptions (policy-file and approvals), live vs expired
    candidates = _matching_exception(list(policy.exceptions) + list(exceptions or []), aid, passport)
    live = [e for e in candidates if aware(e.expires) > now]
    for e in candidates:
        if aware(e.expires) <= now:
            reasons.append(f"exception by {e.approver} expired {aware(e.expires):%Y-%m-%d}")
    approver: str | None = None

    outcome: Outcome
    if floor:
        outcome = floor
        reasons += [f"also: {r}" for _, r in soft]  # context only; the floor decides
    elif not soft:
        outcome = "allow"
        reasons.append(f"risk {score} <= {eff_allow}")
        reasons.append(f"trust {passport.trust_level} >= {env.min_trust}")
    elif live:
        exc = max(live, key=lambda e: aware(e.expires))
        outcome = "allow_with_conditions"
        approver = exc.approver
        reasons += [f"{r} (accepted)" for _, r in soft]
        conditions += [f"{environment} only", f"approved by {exc.approver} until {aware(exc.expires):%Y-%m-%d}: {exc.reason}"]
    else:
        outcome = "block" if any(o == "block" for o, _ in soft) else "quarantine"
        reasons += [r for _, r in soft]

    reasons += [f"compliance: {t}" for t in compliance_tags(findings, policy)]
    return Decision(
        artifact_id=aid,
        environment=environment,
        outcome=outcome,
        reasons=reasons,
        conditions=conditions,
        risk_score=score,
        trust_level=passport.trust_level,
        findings=findings,
        policy_version=policy.version,
        decided_at=now,
        approver=approver,
    )


def _ago(delta: timedelta) -> str:
    minutes = int(delta.total_seconds() // 60)
    if minutes < 120:
        return f"{minutes} min"
    hours = minutes // 60
    return f"{hours} h" if hours < 48 else f"{hours // 24} days"
