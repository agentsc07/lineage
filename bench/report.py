"""Render bench/results.json to bench/results.md (Track D)."""
from __future__ import annotations

import json
from pathlib import Path


def _p(x) -> str:
    return "–" if x is None else f"{x:.0%}"


def render(results_json: Path, out_md: Path) -> None:
    r = json.loads(results_json.read_text())
    lines = ["# LineageBench results", "", f"Generated {r['generated']} · {r['corpus_items']} labelled inert artifacts · "
             f"GPU hours logged (all jobs): **{r['cost']['gpu_hours_logged_total']}**", ""]
    for mode, m in r["modes"].items():
        o = m["overall"]
        lines += [f"## {mode}", "",
                  f"Overall: **TPR {_p(o['tpr'])}** ({o['n_malicious']} malicious) · **FPR {_p(o['fpr'])}** ({o['n_benign']} benign)", "",
                  "| category | malicious | TPR | benign | FPR | AUROC | errors |", "|---|---|---|---|---|---|---|"]
        for cat, c in sorted(m["categories"].items()):
            au = f"{c['auroc']:.2f}" if c.get("auroc") is not None else "–"
            lines.append(f"| {cat} | {c['n_malicious']} | {_p(c['tpr'])} | {c['n_benign']} | {_p(c['fpr'])} | {au} | {c['errors']} |")
        lines += ["", "| check | n | p50 | p95 |", "|---|---|---|---|"]
        for chk, l in m["latency"].items():
            lines.append(f"| {chk} | {l['n']} | {l['p50_s'] * 1000:.0f} ms | {l['p95_s'] * 1000:.0f} ms |")
        missed = [i for i in m["items"] if i["label"] == "malicious" and not i["positive"]]
        fps = [i for i in m["items"] if i["label"] == "benign" and i["positive"]]
        lines += ["", f"Missed malicious ({len(missed)}): " + (", ".join(i["id"] for i in missed) or "none"),
                  f"False positives ({len(fps)}): " + (", ".join(i["id"] for i in fps) or "none"), ""]
    lines += ["## Notes", "", r["cost"]["note"], ""]
    out_md.write_text("\n".join(lines))
