"""Run Lineage over the corpus; write bench/results.json (detection, TPR/FPR, latency, cost) (Track D)."""
from __future__ import annotations

import csv
import json
import os
import statistics
import sys
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.environ.setdefault("LINEAGE_OFFLINE", "1")  # no live OSV calls: results must be reproducible

NOW = datetime(2026, 10, 25, tzinfo=timezone.utc)
NO_WORKER = "http://127.0.0.1:9"  # closed port: forces the "GPU worker unreachable" fallback
LORA_THRESHOLD = 0.5


def _check_intake(item: dict, root: Path, policy, gpu_url: str, env: str = "dev"):
    """Flagged = blocked, or risk above the policy's allow threshold. (Outcome alone would count the policy's
    mandatory human-approval quarantine of every tool as a detection.)"""
    from lineage.intake.pipeline import run_to_decision
    d, _ = run_to_decision(item["kind"], str(root / item["path"]), env, policy, "bench", gpu_url=gpu_url, now=NOW)
    return (d.outcome == "block" or d.risk_score > policy.thresholds.allow), {"outcome": d.outcome, "risk": d.risk_score,
                                                   "findings": sorted({f.id for f in d.findings if f.severity != "info"})}


def _check_bind(item: dict, root: Path, policy, gpu_url: str, env: str = "dev"):
    from lineage.bind import check
    from lineage.schemas.passport import SignedPassport
    from lineage.signing.keys import load_public_key
    d = root / item["path"]
    signed = SignedPassport.model_validate_json((d / "passport.signed.json").read_text())
    pub = load_public_key(root / "_keys" / "bench" / "default.pub")
    problems = check(d / "model", signed, policy, public_key=pub)
    return bool(problems), {"problems": problems[:3]}


def _check_tokenizer(item: dict, root: Path, policy, gpu_url: str, env: str = "dev"):
    from lineage.inspect import tokenizer
    d = root / item["path"]
    fs = [f for f in tokenizer.scan(d / "model", d / item["base"]) if f.severity != "info"]
    return bool(fs), {"findings": sorted({f.id for f in fs})}


def _check_lora(item: dict, root: Path, policy, gpu_url: str, env: str = "dev"):
    from gpu_worker import weights_api as w
    parent = w.identify_parent(item["path"]).parent
    r = w.spectral_score(item["path"], parent or "")
    return r.score >= LORA_THRESHOLD, {"score": r.score, "parent": parent}


CHECKS = {"intake": _check_intake, "bind": _check_bind, "tokenizer_diff": _check_tokenizer, "lora_weights": _check_lora}


def _pct(xs: list[float], q: float) -> float:
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(q * len(xs)))] if xs else 0.0


def _auroc(pos: list[float], neg: list[float]) -> float | None:
    if not pos or not neg:
        return None
    return sum((p > n) + 0.5 * (p == n) for p in pos for n in neg) / (len(pos) * len(neg))


def gpu_hours_logged() -> float:
    f = ROOT / "bench" / "cost_log.csv"
    if not f.exists():
        return 0.0
    return round(sum(float(r["gpu_hours"]) for r in csv.DictReader(f.open())), 3)


def run_mode(corpus_dir: Path, policy, gpu_url: str, env: str = "dev") -> dict:
    manifest = json.loads((corpus_dir / "manifest.json").read_text())
    rows = []
    for item in manifest["items"]:
        t0 = time.perf_counter()
        try:
            positive, detail = CHECKS[item["check"]](item, corpus_dir, policy, gpu_url, env)
        except Exception as e:  # noqa: BLE001 - record, never abort the whole bench
            positive, detail = False, {"error": f"{type(e).__name__}: {e}"[:200]}
        rows.append({**{k: item[k] for k in ("id", "category", "label", "check")}, "positive": positive,
                     "seconds": round(time.perf_counter() - t0, 4), **detail})
    cats: dict[str, dict] = {}
    by_cat = defaultdict(list)
    for r in rows:
        by_cat[r["category"]].append(r)
    for cat, rs in by_cat.items():
        mal, ben = [r for r in rs if r["label"] == "malicious"], [r for r in rs if r["label"] == "benign"]
        tp, fp = sum(r["positive"] for r in mal), sum(r["positive"] for r in ben)
        c = {"n_malicious": len(mal), "n_benign": len(ben), "tp": tp, "fp": fp,
             "tpr": tp / len(mal) if mal else None, "fpr": fp / len(ben) if ben else None,
             "errors": sum("error" in r for r in rs)}
        if cat == "lora_backdoor":
            c["auroc"] = _auroc([r["score"] for r in mal if "score" in r], [r["score"] for r in ben if "score" in r])
        cats[cat] = c
    mal_all = [r for r in rows if r["label"] == "malicious"]
    ben_all = [r for r in rows if r["label"] == "benign"]
    lat: dict[str, dict] = {}
    for chk in CHECKS:
        xs = [r["seconds"] for r in rows if r["check"] == chk]
        if xs:
            lat[chk] = {"n": len(xs), "p50_s": round(statistics.median(xs), 4), "p95_s": round(_pct(xs, 0.95), 4)}
    return {"gpu_url": gpu_url, "environment": env, "categories": cats, "latency": lat,
            "overall": {"n": len(rows), "n_malicious": len(mal_all), "n_benign": len(ben_all),
                        "tpr": sum(r["positive"] for r in mal_all) / max(1, len(mal_all)),
                        "fpr": sum(r["positive"] for r in ben_all) / max(1, len(ben_all))},
            "items": rows}


def run_bench(corpus_dir: Path, out_json: Path, gpu_url: str | None = None) -> None:
    from lineage.schemas.policy import PolicyPack
    policy = PolicyPack.from_yaml(ROOT / "examples" / "policy.org.yaml")
    modes = {"dev, no GPU worker": run_mode(corpus_dir, policy, NO_WORKER, "dev"),
             "staging (deep stages on), no GPU worker": run_mode(corpus_dir, policy, NO_WORKER, "staging")}
    if gpu_url:
        modes["staging (deep stages on), with GPU worker"] = run_mode(corpus_dir, policy, gpu_url, "staging")
    out_json.write_text(json.dumps({
        "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "corpus_items": json.loads((corpus_dir / "manifest.json").read_text())["items"].__len__(),
        "cost": {"gpu_hours_logged_total": gpu_hours_logged(),
                 "note": "GPU hours are one-off (bank training, evaluation). Per-intake GPU time is the 'seconds' of GPU-backed checks."},
        "modes": modes}, indent=1))


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--gpu-url", default=None, help="also run with the GPU worker at this URL")
    a = ap.parse_args()
    run_bench(ROOT / "bench" / "corpus", ROOT / "bench" / "results.json", a.gpu_url)
    from bench.report import render
    render(ROOT / "bench" / "results.json", ROOT / "bench" / "results.md")
