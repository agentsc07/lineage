"""After-refactor benchmark (REFACTOR_SPEC 11.3): static-only and reviewer-through-the-hosted-API, over the in-repo sets.

    uv run python -m bench.run_after_refactor --mode static               # no network, no key
    NVIDIA_API_KEY=... uv run python -m bench.run_after_refactor --mode hosted
    uv run python -m bench.report_after_refactor                           # writes bench/results_after_refactor.md

Each set is run with the policy as shipped (unrun checks priced: a model without the GPU worker carries risk in staging) and with unrun
checks priced at `info` (isolates what the detectors do, comparable with the frozen run where the GPU checks were simply absent). Writes
bench/after_refactor_<mode>.json. `never overwrites results_final.md`.
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

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.environ.setdefault("LINEAGE_OFFLINE", "1")

from bench import run_ablation as ab  # noqa: E402
from bench.run_bench import NO_WORKER  # noqa: E402
from lineage.schemas.policy import PolicyPack  # noqa: E402

SETS = [("in-sample (bench/corpus)", "bench/corpus"), ("dev (bench/corpus_holdout)", "bench/corpus_holdout"), ("FINAL synthetic (bench/corpus_final)", "bench/corpus_final")]


def policies() -> dict[str, PolicyPack]:
    base = PolicyPack.from_yaml(ROOT / "examples" / "policy.org.yaml")
    info = base.model_copy(update={"unrun_checks": {"default": {"dev": "info", "staging": "info", "prod": "info"}}})
    return {"as_shipped": base, "unrun_info": info}


def run_set(path: str, mode: str, policy: PolicyPack, limit: int | None) -> list[dict]:
    root = ROOT / path
    manifest = json.loads((root / "manifest.json").read_text())
    items = manifest["items"] if isinstance(manifest, dict) else manifest
    if limit:
        items = ab.sample(items, limit)
    gpu_url = NO_WORKER if mode == "static" else None  # None: no worker named, the hosted API is used
    ab.STATIC_TIMEOUT_S = 120 if mode == "static" else 900
    rows = []
    for n, item in enumerate(items, 1):
        calls0 = _totals()
        row = ab.run_item(item, root, policy, gpu_url, None)
        calls1 = _totals()
        row["reviewer_calls"], row["reviewer_s"] = calls1["calls"] - calls0["calls"], calls1["latency_s"] - calls0["latency_s"]
        row["reviewer_tokens"] = (calls1["completion_tokens"] + calls1["prompt_tokens"]) - (calls0["completion_tokens"] + calls0["prompt_tokens"])
        rows.append(row)
        if n % 20 == 0:
            print(f"  {path}: {n}/{len(items)}", file=sys.stderr, flush=True)
    return rows


def _totals() -> dict:
    try:
        from gpu_worker import reviewer_llm

        return reviewer_llm.totals()
    except ImportError:
        return {"calls": 0, "latency_s": 0.0, "prompt_tokens": 0, "completion_tokens": 0}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["static", "hosted"], required=True)
    ap.add_argument("--limit", type=int)
    ap.add_argument("--sets", nargs="*", help="substring of a set name")
    ap.add_argument("--only-policy", choices=["as_shipped", "unrun_info"])
    a = ap.parse_args()
    if a.mode == "hosted":
        if not (os.environ.get("NVIDIA_API_KEY") or os.environ.get("LINEAGE_LLM_API_KEY")):
            sys.exit("hosted mode needs NVIDIA_API_KEY (or LINEAGE_LLM_API_KEY)")
        os.environ.pop("LINEAGE_GPU_URL", None)
        os.environ.pop("LINEAGE_VLLM_URL", None)
        os.environ.setdefault("LINEAGE_REVIEW_CACHE", str(ROOT / "bench" / ".review_cache"))
    out = {"generated": datetime.now(timezone.utc).isoformat(), "mode": a.mode, "model": os.environ.get("LINEAGE_LLM_MODEL") if a.mode == "hosted" else None,
           "review_mode": os.environ.get("LINEAGE_REVIEW_MODE", "precise"), "sets": {}}
    for label, path in SETS:
        if a.sets and not any(x in label or x in path for x in a.sets):
            continue
        out["sets"][label] = {}
        for pname, pol in policies().items():
            if a.only_policy and pname != a.only_policy:
                continue
            t0 = time.time()
            rows = run_set(path, a.mode, pol, a.limit)
            out["sets"][label][pname] = {"rows": rows, "rates": ab.rates(rows), "seconds": round(time.time() - t0, 1),
                                         "p50_ms": statistics.median(r["seconds"] for r in rows) * 1000, "p95_ms": ab._pct([r["seconds"] for r in rows], 0.95) * 1000}
            print(f"{label} [{pname}] {a.mode}: TPR {out['sets'][label][pname]['rates']['tpr']} FPR {out['sets'][label][pname]['rates']['fpr']}", file=sys.stderr, flush=True)
    (ROOT / "bench" / f"after_refactor_{a.mode}.json").write_text(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
