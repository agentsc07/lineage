"""Reviewer ablation (Track D): each item set run twice, static-only (GPU worker off) vs static+reviewer (worker on).

    uv run python -m bench.run_ablation                      # every dev set that exists
    uv run python -m bench.run_ablation --include-final      # also the final sets (do this ONCE, when told to)
    uv run python -m bench.run_ablation --limit 10 --out bench/ablation_sample   # quick smoke test on a stratified sample

A set is a directory with a `manifest.json` in the LineageBench format (bench/build_corpus.py): items with
id, label (malicious|benign), category, kind, check, path (relative to the set directory). Sets listed in SETS whose directory does
not exist yet are reported as "missing", not as errors. Final sets are refused unless --include-final is given, so they are
run exactly once.

Per set and mode: TPR, FPR (Wilson 95%), then for static -> static+reviewer: the decisions that changed (direction, item ids, risk
delta), the latency added, and GPU-seconds per artifact. "Worker on" enables everything the worker serves (reviewer LLM, deep
checks), so each changed decision also records whether the reviewer LLM was actually called for that item (from GET /review/stats
deltas; items run one at a time so the deltas are exact).

Flagged = decision `block` OR risk > policy allow threshold (benign pickles blocked only by `allow_pickle: false` are counted as policy blocks, not false positives) (as in bench/run_bench.py). Checks other than `intake` (bind,
tokenizer_diff, lora_weights) never use the worker's reviewer; they run once and count identically in both modes.
GPU-seconds = wall time of the reviewer LLM calls (the card is dedicated and calls are sequential, so busy time ~ GPU time);
the policy model and weight checks are not included.
"""
from __future__ import annotations

import argparse
import json
import os
import statistics
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.environ.setdefault("LINEAGE_OFFLINE", "1")

from bench.report import _wilson  # noqa: E402
from bench.run_bench import CHECKS, NO_WORKER  # noqa: E402

GPU_URL = os.environ.get("LINEAGE_GPU_URL", "http://127.0.0.1:8800")
# name, directory, phase. Sets that do not exist yet are reported as missing.
SETS = [
    {"name": "corpus", "dir": "bench/corpus", "phase": "dev"},
    {"name": "corpus_holdout", "dir": "bench/corpus_holdout", "phase": "dev"},
    {"name": "pypi_top200_dev", "dir": "bench/corpus_pypi_top200_dev", "phase": "dev"},
    {"name": "hf_templates", "dir": "bench/corpus_hf_templates", "phase": "dev"},
    {"name": "corpus_final", "dir": "bench/corpus_final", "phase": "final"},
    {"name": "pypi_201_400", "dir": "bench/corpus_pypi_201_400", "phase": "final"},
    {"name": "hf_templates_final", "dir": "bench/corpus_hf_templates_final", "phase": "final"},
]


def _stats(url: str) -> dict:
    try:
        return httpx.get(url + "/review/stats", timeout=5).json()
    except httpx.HTTPError:
        return {"calls": 0, "latency_s": 0.0, "prompt_tokens": 0, "completion_tokens": 0}


def _pct(xs: list[float], q: float) -> float:
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(q * len(xs)))] if xs else 0.0


def sample(items: list[dict], n: int) -> list[dict]:
    """Stratified, deterministic: alternate malicious / benign across categories so a small sample still has both."""
    mal = [i for i in items if i["label"] == "malicious" and i["check"] == "intake"]
    ben = [i for i in items if i["label"] == "benign" and i["check"] == "intake"]
    out = []
    half = (n + 1) // 2
    for pool, take in ((mal, half), (ben, n - half)):
        step = max(1, len(pool) // max(1, take))  # evenly spread so categories are covered
        out += pool[::step][:take]
    return out


def run_item(item: dict, root: Path, policy, gpu_url: str, worker: str | None) -> dict:
    before = _stats(worker) if worker else None
    t0 = time.perf_counter()
    try:
        positive, detail = CHECKS[item["check"]](item, root, policy, gpu_url, "staging")
        err = None
    except Exception as e:  # noqa: BLE001 - recorded, never aborts the run
        positive, detail, err = False, {}, f"{type(e).__name__}: {e}"[:200]
    row = {"id": item["id"], "label": item["label"], "category": item["category"], "check": item["check"],
           "flagged": bool(positive), "seconds": time.perf_counter() - t0, "error": err,
           "outcome": detail.get("outcome"), "risk": detail.get("risk"), "findings": detail.get("findings"),
           "policy_block": bool(detail.get("policy_block"))}
    if worker:
        after = _stats(worker)
        row["reviewer_calls"] = after["calls"] - before["calls"]
        row["reviewer_llm_s"] = after["latency_s"] - before["latency_s"]
        row["reviewer_tokens"] = after["completion_tokens"] - before["completion_tokens"]
    return row


def rates(rows: list[dict]) -> dict:
    mal = [r for r in rows if r["label"] == "malicious"]
    ben = [r for r in rows if r["label"] == "benign"]
    tp = sum(r["flagged"] for r in mal)
    # a benign pickle refused only because policy forbids the format is a policy block, reported separately (as in bench/run_bench.py)
    pb = sum(r["flagged"] and r.get("policy_block", False) for r in ben)
    fp = sum(r["flagged"] and not r.get("policy_block", False) for r in ben)
    tl, th = _wilson(tp, len(mal))
    fl, fh = _wilson(fp, len(ben))
    return {"n": len(rows), "n_malicious": len(mal), "n_benign": len(ben), "tp": tp, "fp": fp, "policy_blocked": pb,
            "tpr": tp / len(mal) if mal else None, "tpr_ci95": [tl, th] if mal else None,
            "fpr": fp / len(ben) if ben else None, "fpr_ci95": [fl, fh] if ben else None,
            "errors": sum(1 for r in rows if r["error"])}


def compare(static: list[dict], rev: list[dict]) -> dict:
    changed = {"raised_to_flagged": [], "lowered_to_unflagged": [], "outcome_changed_same_flag": []}
    for a, b in zip(static, rev):
        assert a["id"] == b["id"]
        entry = {"id": a["id"], "label": a["label"], "risk_static": a["risk"], "risk_reviewer": b["risk"],
                 "outcome_static": a["outcome"], "outcome_reviewer": b["outcome"], "reviewer_called": b.get("reviewer_calls", 0) > 0}
        if not a["flagged"] and b["flagged"]:
            entry["effect"] = "true positive gained" if a["label"] == "malicious" else "false positive introduced"
            changed["raised_to_flagged"].append(entry)
        elif a["flagged"] and not b["flagged"]:
            entry["effect"] = "true positive LOST" if a["label"] == "malicious" else "false positive removed"
            changed["lowered_to_unflagged"].append(entry)
        elif a["outcome"] != b["outcome"]:
            changed["outcome_changed_same_flag"].append(entry)
    changed["n_changed"] = sum(len(v) for v in changed.values() if isinstance(v, list))
    changed["risk_deltas"] = [b["risk"] - a["risk"] for a, b in zip(static, rev) if a["risk"] is not None and b["risk"] is not None]
    changed["n_risk_changed"] = sum(1 for d in changed["risk_deltas"] if d)
    changed["n_risk_lowered"] = sum(1 for d in changed["risk_deltas"] if d < 0)
    return changed


def cost(static: list[dict], rev: list[dict]) -> dict:
    intake = [(a, b) for a, b in zip(static, rev) if a["check"] == "intake"]
    added = [b["seconds"] - a["seconds"] for a, b in intake]
    called = [b for _, b in intake if b.get("reviewer_calls", 0) > 0]
    llm_s = sum(b.get("reviewer_llm_s", 0.0) for b in rev)
    n = len(rev)
    return {"n_intake_items": len(intake), "n_reviewed": len(called),
            "latency_added_s": {"mean": statistics.mean(added) if added else 0.0, "p50": _pct(added, .5), "p95": _pct(added, .95),
                                "total": sum(added)},
            "latency_added_s_reviewed_only": {"mean": statistics.mean([b["seconds"] - a["seconds"] for a, b in intake if b.get("reviewer_calls", 0) > 0])
                                              if called else 0.0},
            "reviewer_calls": sum(b.get("reviewer_calls", 0) for b in rev), "reviewer_completion_tokens": sum(b.get("reviewer_tokens", 0) for b in rev),
            "gpu_seconds_total": llm_s, "gpu_seconds_per_artifact": llm_s / n if n else 0.0,
            "gpu_seconds_per_reviewed_artifact": llm_s / len(called) if called else 0.0}


def run_set(spec: dict, policy, worker: str, limit: int | None) -> dict:
    root = ROOT / spec["dir"]
    manifest = json.loads((root / "manifest.json").read_text())
    items = manifest["items"]
    if limit:
        items = sample(items, limit)
    static, rev = [], []
    t_start = time.perf_counter()
    for it in items:
        a = run_item(it, root, policy, NO_WORKER, None)
        if it["check"] == "intake":
            b = run_item(it, root, policy, worker, worker)
        else:  # the worker's reviewer is not involved: identical by construction, do not pay twice
            b = {**a, "reviewer_calls": 0, "reviewer_llm_s": 0.0, "reviewer_tokens": 0}
        static.append(a)
        rev.append(b)
        print(f"  {spec['name']}: {it['id']:32s} static={'F' if a['flagged'] else '.'} +reviewer={'F' if b['flagged'] else '.'}"
              f" calls={b.get('reviewer_calls', 0)}", flush=True)
    return {"status": "ran", "dir": spec["dir"], "phase": spec["phase"], "n_items": len(items), "sampled": bool(limit), "wall_s": time.perf_counter() - t_start,
            "static_only": rates(static), "static_plus_reviewer": rates(rev),
            "changes": compare(static, rev), "cost": cost(static, rev), "items": {"static": static, "reviewer": rev}}


def render(result: dict, path: Path) -> None:
    f = lambda x: "–" if x is None else f"{x:.0%}"  # noqa: E731
    ci = lambda r, k: "" if r.get(k) is None else f" ({r[k][0]:.0%}–{r[k][1]:.0%})"  # noqa: E731
    L = ["# Reviewer ablation", "",
         f"Generated {result['generated']} · worker `{result['worker_url']}` · reviewer `{result['reviewer_llm']}` · "
         f"{'**SAMPLE RUN, not final**' if result['sample'] else 'full run'} · flagged = block or risk > allow threshold · Wilson 95% intervals.", "",
         "Static-only = GPU worker off (deterministic scanners). Static+reviewer = worker on (reviewer LLM and the other deep checks the worker serves).", "",
         "| set | n | static TPR | static FPR | +reviewer TPR | +reviewer FPR | decisions changed | latency added (mean / p95) | GPU-s per artifact |",
         "|---|---|---|---|---|---|---|---|---|"]
    for name, s in result["sets"].items():
        if s["status"] != "ran":
            L.append(f"| {name} | – | not available: {s['status']} | | | | | | |")
            continue
        a, b, c, k = s["static_only"], s["static_plus_reviewer"], s["changes"], s["cost"]
        L.append(f"| {name} | {s['n_items']} ({a['n_malicious']} mal / {a['n_benign']} ben) | {f(a['tpr'])}{ci(a, 'tpr_ci95')} | {f(a['fpr'])}{ci(a, 'fpr_ci95')} | "
                 f"{f(b['tpr'])}{ci(b, 'tpr_ci95')} | {f(b['fpr'])}{ci(b, 'fpr_ci95')} | {c['n_changed']} | "
                 f"{k['latency_added_s']['mean']:.2f} s / {k['latency_added_s']['p95']:.2f} s | {k['gpu_seconds_per_artifact']:.2f} |")
    total_calls = sum(s["cost"]["reviewer_calls"] for s in result["sets"].values() if s["status"] == "ran")
    if total_calls == 0:
        L += ["", "> **Warning: the reviewer LLM was never called by intake in this run** (0 calls on the worker). Any difference between the two "
              "modes comes from the worker's other deep checks, not from the reviewer. Intake must call `/review/code` "
              "(`lineage.inspect.llm_review`) for this ablation to measure the reviewer."]
    for name, s in result["sets"].items():
        if s["status"] != "ran":
            continue
        c, k = s["changes"], s["cost"]
        L += ["", f"## {name}", "",
              f"- Reviewer called on {k['n_reviewed']} of {k['n_intake_items']} intake items; {k['reviewer_calls']} LLM calls, "
              f"{k['reviewer_completion_tokens']} generated tokens; {k['gpu_seconds_total']:.1f} GPU-s total "
              f"({k['gpu_seconds_per_reviewed_artifact']:.2f} per reviewed artifact); latency added on reviewed items {k['latency_added_s_reviewed_only']['mean']:.2f} s on average.",
              f"- Risk scores changed on {c['n_risk_changed']} items; lowered on {c['n_risk_lowered']} (must be 0: the worker may only raise)."]
        for key, title in (("raised_to_flagged", "Flag raised (static: not flagged → with reviewer: flagged)"),
                           ("lowered_to_unflagged", "Flag lowered (static: flagged → with reviewer: not flagged)"),
                           ("outcome_changed_same_flag", "Outcome changed, flag unchanged")):
            rows = c[key]
            L.append(f"- {title}: " + (", ".join(f"`{r['id']}` ({r['effect'] if 'effect' in r else r['outcome_static'] + '→' + r['outcome_reviewer']}"
                                                    f"{'' if r['reviewer_called'] else ', reviewer not called'})" for r in rows) or "none"))
    path.write_text("\n".join(L) + "\n")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sets", nargs="*", help="names from SETS (default: every dev set that exists)")
    ap.add_argument("--include-final", action="store_true", help="also run the final sets (once!)")
    ap.add_argument("--limit", type=int, help="stratified sample of N intake items per set (smoke test)")
    ap.add_argument("--out", default=str(ROOT / "bench" / "ablation"), help="output prefix (.json and .md are appended)")
    ap.add_argument("--worker", default=GPU_URL)
    a = ap.parse_args()
    from lineage.schemas.policy import PolicyPack
    policy = PolicyPack.from_yaml(ROOT / "examples" / "policy.org.yaml")
    health = httpx.get(a.worker + "/health", timeout=10).json()
    if not health["endpoints"].get("/review/code"):
        sys.exit("reviewer is not up on the worker (start scripts/serve_reviewer.sh); refusing to run an ablation without it")
    result = {"generated": datetime.now(timezone.utc).isoformat(timespec="seconds"), "worker_url": a.worker,
              "reviewer_llm": health.get("reviewer_llm"), "sample": bool(a.limit), "sets": {}}
    for spec in SETS:
        if a.sets and spec["name"] not in a.sets:
            continue
        if spec["phase"] == "final" and not a.include_final:
            result["sets"][spec["name"]] = {"status": "final set: pass --include-final to run it"}
            continue
        if not (ROOT / spec["dir"] / "manifest.json").exists():
            result["sets"][spec["name"]] = {"status": f"missing ({spec['dir']}/manifest.json not found)"}
            continue
        print(f"== {spec['name']}", flush=True)
        result["sets"][spec["name"]] = run_set(spec, policy, a.worker, a.limit)
    out = Path(a.out)
    out.with_suffix(".json").write_text(json.dumps(result, indent=1, default=str))
    render(result, out.with_suffix(".md"))
    print(f"wrote {out.with_suffix('.json')} and {out.with_suffix('.md')}")


if __name__ == "__main__":
    main()
