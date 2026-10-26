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
    lines += _reviewer_section(results_json.with_name("reviewer.json"))
    lines += ["## Notes", "", r["cost"]["note"], ""]
    out_md.write_text("\n".join(lines))


def _wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    if n == 0:
        return (0.0, 1.0)
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * ((p * (1 - p) / n + z * z / (4 * n * n)) ** 0.5) / d
    return (max(0.0, c - h), min(1.0, c + h))


def _reviewer_section(path: Path) -> list[str]:
    """Reviewer LLM (Nemotron Nano 9B v2 on vLLM) precision/recall, latency and tokens/sec from bench/reviewer.json."""
    if not path.exists():
        return []
    r = json.loads(path.read_text())
    L = r["latency"]
    out = ["## Reviewer (LLM)", "",
           f"`{r['reviewer_llm']}` served by vLLM; prosecutor → defender → judge, JSON-schema constrained. Flagged = verdict suspicious/malicious. "
           f"{r['n_items']} requests, {r['n_errors']} errors. Wilson 95% intervals; **small n, and the first four groups were used to tune prompts**.", "",
           "| group | malicious | recall (95% CI) | benign | false positives | precision |", "|---|---|---|---|---|---|"]
    for name, g in r["by_group"].items():
        lo, hi = _wilson(g["tp"], g["n_malicious"])
        fp = f"{g['fp']}/{g['n_benign']}" if g["n_benign"] else "–"
        out.append(f"| {name} | {g['n_malicious']} | {_p(g['recall'])} ({lo:.0%}–{hi:.0%}) | {g['n_benign']} | {fp} | {_p(g['precision'])} |")
    o = r["overall"]
    out += ["", f"Tuned set overall: precision **{_p(o['precision'])}**, recall **{_p(o['recall'])}** "
            f"({o['tp']} TP, {o['fp']} FP, {o['fn']} FN, {o['tn']} TN). Reviewer-bait reported as its own claim: {_p(r['bait_reported_as_claim'])}.", "",
            "| latency | p50 | p95 | mean |", "|---|---|---|---|",
            f"| per LLM call | {L['per_llm_call_s']['p50']:.2f} s | {L['per_llm_call_s']['p95']:.2f} s | – |",
            f"| per request (end to end, {L['llm_calls_per_request_mean']:.1f} calls on average) | {L['request_wall_s']['p50']:.2f} s | "
            f"{L['request_wall_s']['p95']:.2f} s | {L['request_wall_s']['mean']:.2f} s |", "",
            f"Tokens: {r['tokens']['prompt']:,} prompt, {r['tokens']['completion']:,} generated · "
            f"**{r['tokens']['generation_tokens_per_s_incl_prefill']:.0f} tokens/s** (generated tokens / LLM time, batch 1, bf16 on one L40S). {r['notes']}", ""]
    return out
