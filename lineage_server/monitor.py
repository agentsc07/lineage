"""Continuous watch: re-query advisories for admitted packages, raise alerts + blast radius.

One `tick` does, in order:
1. For every admitted package, ask the advisory sources (OSV via the Inspector's `package_osv`, plus an optional
   local feed file, `LINEAGE_ADVISORY_FEED`) what is known *now*. Advisories not already on record are stored as
   findings, the package is re-decided, and an `advisory` alert is raised.
2. Every descendant of an alerted package is flagged (a `WATCH.PARENT.ADVISORY` finding raises its risk and it is
   re-decided); the alert carries that blast radius.
3. Human approvals that have expired are re-evaluated; a lapsed approval raises a `drift` alert.
4. Ghost packages (SBOM components and dependencies that were never admitted) get the same advisory lookup; the alert carries the
   blast radius through the ghost (P6).
5. Hub drift for every `hf:` artifact: the tracked branch moved (`WATCH.UPSTREAM.CHANGED`, info: the admitted bytes are pinned) or the
   repo disappeared (`WATCH.UPSTREAM.REMOVED`, high: re-decided).
6. A trusted-publisher key that is now in `revoked_keys`: everything signed by it is re-decided with `PROV.SIGNATURE.REVOKED_KEY`.
7. A policy version newer than an artifact's last decision: re-decide it.

Ticks are idempotent: a second tick with nothing new raises nothing.

Local feed format (for air-gapped installs and the demo):
`{"<name>==<version>": [{"id": "GHSA-xxxx", "severity": "high", "summary": "..."}]}`.
"""
from __future__ import annotations

import json
import logging
import os
import sqlite3
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path

from lineage.risk import SEVERITY_WEIGHT
from lineage.schemas.artifact import Alert, MonitorTick
from lineage.schemas.finding import Evidence, Finding
from lineage.schemas.policy import PolicyPack
from lineage_server import graph, models, policy_store, service

log = logging.getLogger(__name__)
SEV_ORDER = ["info", "low", "medium", "high", "critical"]
Lookup = Callable[[str, str], list[Finding]]


def feed_findings(path: Path | str | None, name: str, version: str) -> list[Finding]:
    if not path or not Path(path).exists():
        return []
    entries = json.loads(Path(path).read_text()).get(f"{name}=={version}", [])
    return [
        Finding(
            id=f"PKG.OSV.{e['id']}",
            title=f"{e['id']}: {e.get('summary', 'advisory')}",
            severity=e.get("severity", "high"),
            category="code",
            stage="S3",
            evidence=[Evidence(kind="field", ref=e["id"], detail=f"{name}=={version} (local advisory feed)")],
            score=SEVERITY_WEIGHT[e.get("severity", "high")],
            source="deterministic",
        )
        for e in entries
    ]


def default_lookup(name: str, version: str) -> list[Finding]:
    """OSV through the Inspector (when implemented), plus the local feed. Network or scanner failure is logged
    and treated as 'nothing new' for that package; it does not abort the tick."""
    out = feed_findings(os.environ.get("LINEAGE_ADVISORY_FEED"), name, version)
    try:
        from lineage.inspect import package_osv

        # ttl=0: the watch must see advisories published after the last cache fill. Info findings (OSV unreachable,
        # placeholder version) say nothing about advisories, so they are not alerts.
        out += [f for f in package_osv.scan(name, version, ttl=0) if f.severity != "info"]
    except NotImplementedError:
        pass
    except Exception as e:  # noqa: BLE001
        log.warning("OSV lookup failed for %s==%s: %s", name, version, e)
    return out


def _key(f: Finding) -> tuple:
    return f.id, tuple(e.ref for e in f.evidence)


def _top(findings: list[Finding]) -> str:
    return max((f.severity for f in findings), key=SEV_ORDER.index)


def _flag(pkg_label: str, pkg_id: str, new: list[Finding]) -> Finding:
    sev = min(_top(new), "high", key=SEV_ORDER.index)  # a parent advisory raises risk, it does not hard-block
    return Finding(
        id="WATCH.PARENT.ADVISORY",
        title=f"Dependency {pkg_label} has a new advisory ({', '.join(f.id.removeprefix('PKG.OSV.') for f in new)[:80]})",
        severity=sev,  # type: ignore[arg-type]
        category="provenance",
        stage="S2",
        evidence=[Evidence(kind="field", ref=pkg_id, detail="advisory published after admission")],
        score=SEVERITY_WEIGHT[sev],
        source="deterministic",
    )


def _simple_finding(fid: str, title: str, sev: str, ref: str, detail: str, stage: str = "S2") -> Finding:
    return Finding(id=fid, title=title, severity=sev, category="provenance", stage=stage,  # type: ignore[arg-type]
                   evidence=[Evidence(kind="field", ref=ref, detail=detail)], score=SEVERITY_WEIGHT[sev], source="deterministic")


def tick(
    conn: sqlite3.Connection,
    *,
    policy: PolicyPack | None = None,
    lookup: Lookup | None = None,
    now: datetime | None = None,
    hub=None,
) -> MonitorTick:
    now = now or datetime.now(timezone.utc)
    expired = False
    if policy is None:
        policy, expired = policy_store.active(conn, now)
    lookup = lookup or default_lookup
    alerts: list[Alert] = []

    packages = conn.execute(
        "SELECT id, name, version FROM artifacts WHERE artifact_type = 'package'"
        " AND status IN ('admitted', 'admitted_with_conditions') ORDER BY created_at, rowid"
    ).fetchall()
    for row in packages:
        known = {_key(f) for f in models.get_findings(conn, row["id"])}
        new = [f for f in lookup(row["name"], row["version"]) if _key(f) not in known]
        if not new:
            continue
        before = models.artifact_row(conn, row["id"])
        after = service.redecide(conn, row["id"], policy, policy_expired=expired, extra_findings=new, now=now)
        radius = graph.blast_radius(conn, row["id"])
        flag = _flag(f"{row['name']}=={row['version']}", row["id"], new)
        for node in radius:
            if node.status != "revoked":
                service.redecide(conn, node.id, policy, policy_expired=expired, extra_findings=[flag], now=now)
        alerts.append(Alert(
            artifact_id=row["id"],
            kind="advisory",
            severity=_top(new),  # type: ignore[arg-type]
            message=f"{len(new)} new advisory(ies) for {row['name']}=={row['version']}: "
                    f"{'; '.join(f.title for f in new)[:200]}. Decision {before.outcome} -> {after.outcome}; "
                    f"{len(radius)} dependent artifact(s) flagged.",
            blast_radius=graph.blast_radius(conn, row["id"]),
        ))

    # lapsed approvals
    for row in conn.execute("SELECT id, name FROM artifacts WHERE status = 'admitted_with_conditions' ORDER BY rowid").fetchall():
        approvals = models.get_approvals(conn, row["id"])
        if approvals and all(datetime.fromisoformat(a["expires"]) <= now for a in approvals):
            after = service.redecide(conn, row["id"], policy, policy_expired=expired, now=now)
            alerts.append(Alert(
                artifact_id=row["id"], kind="drift", severity="medium",
                message=f"Approval for {row['name']} expired; decision is now {after.outcome}.",
                blast_radius=graph.blast_radius(conn, row["id"]),
            ))

    # ghost packages: SBOM components and dependencies nobody admitted
    ghosts = conn.execute("SELECT * FROM ghosts WHERE artifact_type = 'package' AND version != '' AND version != '*' AND revoked_reason IS NULL").fetchall()
    for g in ghosts:
        seen = set(json.loads(g["advisories"]))
        new = [f for f in lookup(g["name"], g["version"]) if f.id not in seen]
        if not new:
            continue
        conn.execute("UPDATE ghosts SET advisories = ? WHERE id = ?", (json.dumps(sorted(seen | {f.id for f in new})), g["id"]))
        radius = graph.blast_radius(conn, g["id"])
        flag = _flag(f"{g['name']}=={g['version']} (unregistered)", g["id"], new)
        for node in radius:
            if node.status != "revoked":
                service.redecide(conn, node.id, policy, policy_expired=expired, extra_findings=[flag], now=now)
        alerts.append(Alert(artifact_id=g["id"], kind="advisory", severity=_top(new),  # type: ignore[arg-type]
                            message=f"{len(new)} new advisory(ies) for {g['name']}=={g['version']}, a package no one admitted but "
                                    f"{len(radius)} artifact(s) were built with or depend on: {'; '.join(f.title for f in new)[:160]}",
                            blast_radius=radius))
    conn.commit()

    # hub drift
    if hub is not None or os.environ.get("LINEAGE_HUB_URL"):
        alerts += _hub_drift(conn, policy, expired, now, hub)

    # revoked trusted-publisher keys
    for r in conn.execute("SELECT m.artifact_id, m.signer_key, a.name FROM artifact_meta m JOIN artifacts a ON a.id = m.artifact_id"
                          " WHERE m.signer_key IS NOT NULL AND a.status NOT IN ('revoked', 'blocked')").fetchall():
        if r["signer_key"] in policy.revoked_keys and not any(f.id == "PROV.SIGNATURE.REVOKED_KEY" for f in models.get_findings(conn, r["artifact_id"])):
            f = _simple_finding("PROV.SIGNATURE.REVOKED_KEY", f"The key {r['signer_key']} that signed this artifact's passport was revoked; treated as unsigned",
                                "high", "key_id", r["signer_key"])
            after = service.redecide(conn, r["artifact_id"], policy, policy_expired=expired, extra_findings=[f], now=now)
            alerts.append(Alert(artifact_id=r["artifact_id"], kind="revocation", severity="high",
                                message=f"Signing key {r['signer_key']} was revoked; {r['name']} re-decided: {after.outcome}.",
                                blast_radius=graph.blast_radius(conn, r["artifact_id"])))

    # policy changed since the last decision
    stale = [r["id"] for r in conn.execute("SELECT id FROM artifacts WHERE status NOT IN ('revoked') ORDER BY rowid").fetchall()
             if (d := models.latest_decision(conn, r["id"])) is not None and d.policy_version != policy.version]
    if stale:
        changed = 0
        for aid in stale:
            before = models.latest_decision(conn, aid)
            after = service.redecide(conn, aid, policy, policy_expired=expired, now=now)
            changed += before.outcome != after.outcome  # type: ignore[union-attr]
        alerts.append(Alert(artifact_id=stale[0], kind="drift", severity="medium",
                            message=f"Policy changed to {policy.version}: {len(stale)} artifact(s) re-decided, {changed} changed outcome.",
                            blast_radius=[]))
    return MonitorTick(checked=len(packages) + len(ghosts), alerts=alerts, ts=now)


def _hub_drift(conn: sqlite3.Connection, policy: PolicyPack, expired: bool, now: datetime, hub) -> list[Alert]:
    from lineage.intake import fetch

    alerts: list[Alert] = []
    base_url, client = getattr(hub, "base_url", None) or None, getattr(hub, "client", None)
    rows = conn.execute("SELECT m.artifact_id, m.source_id, a.name FROM artifact_meta m JOIN artifacts a ON a.id = m.artifact_id"
                        " WHERE m.source_id LIKE 'hf:%' AND a.status IN ('admitted', 'admitted_with_conditions', 'quarantined')").fetchall()
    for r in rows:
        signed = models.get_signed_passport(conn, r["artifact_id"])
        pinned = signed.passport.predicate.source.commit if signed else None
        known = {_key(f) for f in models.get_findings(conn, r["artifact_id"])}
        repo = r["source_id"][3:]
        try:
            info = fetch.hf_info(repo, None, "model", base_url, client)
        except fetch.NotFound:
            f = _simple_finding("WATCH.UPSTREAM.REMOVED", f"{repo} is gone from the hub", "high", repo, "hub answered 404")
            if _key(f) in known:
                continue
            after = service.redecide(conn, r["artifact_id"], policy, policy_expired=expired, extra_findings=[f], now=now)
            alerts.append(Alert(artifact_id=r["artifact_id"], kind="drift", severity="high",
                                message=f"{repo} was removed upstream; {r['name']} re-decided: {after.outcome}.",
                                blast_radius=graph.blast_radius(conn, r["artifact_id"])))
            continue
        except fetch.AcquireError:
            continue  # unreachable is not drift
        sha = info.get("sha")
        if sha and pinned and sha != pinned:
            f = _simple_finding("WATCH.UPSTREAM.CHANGED", f"{repo} moved from {pinned[:12]} to {sha[:12]} upstream; the admitted bytes are pinned and unchanged",
                                "info", repo, sha)
            if _key(f) in known:
                continue
            service.redecide(conn, r["artifact_id"], policy, policy_expired=expired, extra_findings=[f], now=now)
            alerts.append(Alert(artifact_id=r["artifact_id"], kind="drift", severity="info",
                                message=f"{repo} changed upstream ({pinned[:12]} -> {sha[:12]}). {r['name']} still uses the pinned bytes.",
                                blast_radius=graph.blast_radius(conn, r["artifact_id"])))
    return alerts
