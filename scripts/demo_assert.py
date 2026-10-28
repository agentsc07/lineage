"""Check the data the demo scenario leaves in the database: `python scripts/demo_assert.py <lineage.db>`.

These are the facts the dashboard story and the talk rely on. If the demo data drifts (a renamed artifact, a missing graph edge, a policy whose
publisher names no longer match its keys), this fails with the sentence that is wrong.
"""
from __future__ import annotations

import json
import sqlite3
import sys

import yaml

db, policy_file = sys.argv[1], sys.argv[2]
c = sqlite3.connect(db)
c.row_factory = sqlite3.Row
art = {r["id"]: f"{r['name']}@{r['version']}" for r in c.execute("SELECT id, name, version FROM artifacts")}
ghost = {r["id"]: f"{r['name']}@{r['version']}" for r in c.execute("SELECT id, name, version FROM ghosts")}
label = lambda i: art.get(i) or ghost.get(i, i)  # noqa: E731
edges = {(label(e["parent"]), e["kind"], label(e["child"])) for e in c.execute("SELECT * FROM edges")}
status = {f"{r['name']}@{r['version']}": r["status"] for r in c.execute("SELECT name, version, status FROM artifacts")}
fails: list[str] = []


def need(ok: bool, msg: str) -> None:
    print(("ok   " if ok else "FAIL ") + msg)
    if not ok:
        fails.append(msg)


pol = yaml.safe_load(open(policy_file))
allow = set(pol["publishers"]["allow"])
need(all(t["name"] in allow for t in pol["trusted_publishers"]), f"every trusted publisher key is named in the publisher allow list ({[t['name'] for t in pol['trusted_publishers']]} vs {sorted(allow)})")
need(not [n for n in art.values() if n.endswith("@0.0.0")], f"no catalogue entry has the placeholder version 0.0.0 ({[n for n in art.values() if n.endswith('@0.0.0')]})")
need(status.get("acme-llm@1.4.0") == "admitted" and status.get("acme-llm@1.4.1") == "blocked", "acme-llm 1.4.0 is admitted and 1.4.1 is blocked")
trained = [n for n in art.values() if n.startswith("triage-trained@")]
need(len(trained) == 1, "the trained model is in the catalogue")
if trained:
    t = trained[0]
    need(any(k == "derived_from" and ch == t and p.startswith("triage-base@") for p, k, ch in edges), "graph: the trained model derives from the approved base model (loaded with lineage.load)")
    need(any(k == "trained_on" and ch == t and p.startswith("instructions@") for p, k, ch in edges), "graph: the trained model was trained on the admitted dataset")
    need(any(k == "built_with" and ch == t and p == "acme-llm@1.4.0" for p, k, ch in edges), "graph: the trained model was built with the admitted package acme-llm 1.4.0 (a real node, not an unregistered one)")
    need(not any(k == "trained_on" and ch == t and (p.startswith("triage-base-copy") or p.startswith("triage-ft")) for p, k, ch in edges), "graph: no 'trained on' edge to a blocked look-alike that merely shares a config file")
print(json.dumps({"failed": fails}))
sys.exit(1 if fails else 0)
