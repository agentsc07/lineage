"""Small JSON/SSE formatters used by demo_scenario.sh (stdin in, text out)."""
from __future__ import annotations

import json
import sys
from datetime import datetime, timedelta, timezone

MARK = {"completed": "✓", "failed": "✗", "skipped": "-"}


def stream() -> None:
    """Read an SSE stream; print each finished stage and findings, then a final `VERDICT outcome risk id` line."""
    for line in sys.stdin:
        if not line.startswith("data:"):
            continue
        e = json.loads(line[5:])
        if e["status"] != "started":
            print(f"  {MARK[e['status']]} {e['stage']} {e['name']:<18} {e['message']}", flush=True)
            for f in e["findings"]:
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


def revoke() -> None:
    r = json.load(sys.stdin)
    print(f"  revoked; {len(r['blast_radius'])} downstream artifact(s) flagged: " + ", ".join(n["label"] for n in r["blast_radius"]))


def get() -> None:
    """`get <path>`: print a field (dotted path, ints index lists) from JSON on stdin."""
    v = json.load(sys.stdin)
    for part in sys.argv[2].split("."):
        v = v[int(part)] if part.isdigit() else v[part]
    print(v)


def expiry() -> None:
    print((datetime.now(timezone.utc) + timedelta(days=int(sys.argv[2]))).isoformat())


if __name__ == "__main__":
    {"stream": stream, "tick": tick, "revoke": revoke, "get": get, "expiry": expiry}[sys.argv[1]]()
