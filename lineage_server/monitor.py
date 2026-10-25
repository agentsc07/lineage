"""Continuous watch: re-query advisories for admitted packages, raise alerts + blast radius.

One `tick` does, in order:
1. For every admitted package, ask the advisory sources (OSV via the Inspector's `package_osv`, plus an optional
   local feed file, `LINEAGE_ADVISORY_FEED`) what is known *now*. Advisories not already on record are stored as
   findings, the package is re-decided, and an `advisory` alert is raised.
2. Every descendant of an alerted package is flagged (a `WATCH.PARENT.ADVISORY` finding raises its risk and it is
   re-decided); the alert carries that blast radius.
3. Human approvals that have expired are re-evaluated; a lapsed approval raises a `drift` alert.

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

        out += package_osv.scan(name, version)
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


def tick(
    conn: sqlite3.Connection,
    *,
    policy: PolicyPack | None = None,
    lookup: Lookup | None = None,
    now: datetime | None = None,
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
    return MonitorTick(checked=len(packages), alerts=alerts, ts=now)
