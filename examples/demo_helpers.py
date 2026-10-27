"""Small JSON/SSE formatters used by demo_scenario.sh (stdin in, text out)."""
from __future__ import annotations

import json
import sys
from datetime import datetime, timedelta, timezone

MARK = {"completed": "✓", "failed": "✗", "skipped": "-"}


def _grouped(findings: list[dict]) -> list[dict]:
    """Collapse repeated advisories into one finding (count, worst severity, top 3 ids), as the risk score does."""
    from lineage.risk import group_advisories
    from lineage.schemas.finding import Finding

    return [f.model_dump() for f in group_advisories([Finding.model_validate(f) for f in findings])]


def stream() -> None:
    """Read an SSE stream; print each finished stage and findings, then a final `VERDICT outcome risk id` line."""
    for line in sys.stdin:
        if not line.startswith("data:"):
            continue
        e = json.loads(line[5:])
        if e["status"] != "started":
            print(f"  {MARK[e['status']]} {e['stage']} {e['name']:<18} {e['message']}", flush=True)
            for f in _grouped(e["findings"]):
                ref = f["evidence"][0]["ref"] if f["evidence"] else ""
                print(f"      [{f['severity']}] {f['title']}  {ref}", flush=True)
        d = e.get("decision")
        if d:
            print(f"VERDICT {d['outcome']} {d['risk_score']} {d['artifact_id']}", flush=True)


def tick() -> None:
    t = json.load(sys.stdin)
    print(f"  checked {t['checked']} artifacts, {len(t['alerts'])} alert(s)")
    for a in t["alerts"]:
        print(f"  [{a['severity']}] {a['message']}")
        print("    affected: " + ", ".join(n["label"] for n in a["blast_radius"]))


def spectral() -> None:
    """`spectral <parent>`: print the /weights/spectral response (score, then the most anomalous layers)."""
    r = json.load(sys.stdin)
    score = r["score"]
    print(f"  parent {sys.argv[2]}; weight-space backdoor score {score:.2f} ({'suspicious' if score >= 0.5 else 'looks benign'})")
    for layer, m in sorted(r.get("per_layer", {}).items(), key=lambda kv: -max(kv[1].values(), default=0))[:3]:
        print(f"      {layer}: " + ", ".join(f"{k}={v:.3g}" for k, v in m.items()))


def revoke() -> None:
    r = json.load(sys.stdin)
    print(f"  revoked; {len(r['blast_radius'])} downstream artifact(s) flagged: " + ", ".join(n["label"] for n in r["blast_radius"]))


def get() -> None:
    """`get <path>`: print a field (dotted path, ints index lists) from JSON on stdin."""
    v = json.load(sys.stdin)
    for part in sys.argv[2].split("."):
        v = v[int(part)] if part.isdigit() else v[part]
    print(v)


def trust() -> None:
    """`trust <db> <public key PEM>`: register a signer key as trusted in the registry database."""
    from pathlib import Path

    from lineage.signing.keys import load_public_key
    from lineage_server import db, trust as server_trust

    conn = db.connect(Path(sys.argv[2]))
    db.init_schema(conn)
    server_trust.trust_key(conn, load_public_key(Path(sys.argv[3])), "apollo-data-team")
    conn.commit()


def stamp() -> None:
    """`stamp <lineage.meta.json> <hours>`: set released_at to that many hours ago."""
    import json as _json
    from pathlib import Path

    path = Path(sys.argv[2])
    meta = _json.loads(path.read_text())
    meta["released_at"] = (datetime.now(timezone.utc) - timedelta(hours=float(sys.argv[3]))).isoformat()
    path.write_text(_json.dumps(meta, indent=2))


def hubfile() -> None:
    """`hubfile <artifacts dir> <hub.json>`: the demo hub's records, one per artifact folder, from the (declared) meta files the
    demo artifacts carry. The hub is what makes them `fetched`; inside the artifact they would only be `declared`."""
    import json as _json
    from pathlib import Path

    records = {}
    for d in sorted(Path(sys.argv[2]).iterdir()):
        meta = d / "lineage.meta.json"
        if d.is_dir() and meta.is_file():
            records[d.name] = _json.loads(meta.read_text())
    Path(sys.argv[3]).write_text(_json.dumps(records, indent=2))


def advisory() -> None:
    """`advisory <feed.json> <name==version>`: publish a local advisory for a package."""
    import json as _json
    from pathlib import Path

    Path(sys.argv[2]).write_text(_json.dumps({sys.argv[3]: [
        {"id": "GHSA-demo-7x4q-9m2p", "severity": "high", "summary": "Heap overflow when decoding crafted vocab files"}]}, indent=2))


def expiry() -> None:
    print((datetime.now(timezone.utc) + timedelta(days=int(sys.argv[2]))).isoformat())


if __name__ == "__main__":
    {"stream": stream, "tick": tick, "revoke": revoke, "get": get, "expiry": expiry,
                                  "spectral": spectral, "trust": trust, "stamp": stamp, "advisory": advisory, "hubfile": hubfile}[sys.argv[1]]()
