"""Run the reviewer fixtures through the GPU worker (HTTP) and write bench/reviewer.json (Track D).

Flagged = verdict is suspicious or malicious. Reports precision/recall on malicious vs benign slices, bait detection on the
reviewer-bait group, latency per call (p50/p95, end to end and LLM time) and generation tokens/sec.
"""
from __future__ import annotations

import json
import os
import statistics as st
import time
from datetime import datetime, timezone
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "bench" / "corpus" / "reviewer" / "fixtures.json"
OUT = ROOT / "bench" / "reviewer.json"
URL = os.environ.get("LINEAGE_GPU_URL", "http://127.0.0.1:8800")


def pct(xs: list[float], q: float) -> float:
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(q * len(xs)))] if xs else 0.0


def run(url: str = URL) -> dict:
    items = json.loads(FIXTURES.read_text())
    rows, t_all = [], time.time()
    for it in items:
        path = {"card": "/review/card", "policy": "/review/policy"}.get(it["endpoint"], "/review/code")
        t = time.perf_counter()
        try:
            r = httpx.post(url + path, json=it["request"], timeout=300)
            wall = time.perf_counter() - t
            if r.status_code != 200:
                rows.append({**{k: it[k] for k in ("id", "label", "group")}, "error": f"{r.status_code} {r.text[:120]}", "wall_s": wall})
                continue
            body, h = r.json(), r.headers
            claims = body["claims"]
            rows.append({
                "id": it["id"], "label": it["label"], "group": it["group"], "verdict": body["verdict"],
                "flagged": body["verdict"] != "benign", "n_claims": len(claims),
                "bait_claim": any(c["text"].startswith("Reviewer bait") for c in claims),
                "max_severity": max((c["severity"] for c in claims), key=["info", "low", "medium", "high", "critical"].index, default=None),
                "wall_s": wall, "llm_calls": int(h.get("x-review-calls", 0)), "llm_s": int(h.get("x-review-latency-ms", 0)) / 1000,
                "prompt_tokens": int(h.get("x-review-prompt-tokens", 0)), "completion_tokens": int(h.get("x-review-completion-tokens", 0)),
                "claims": [{k: c[k] for k in ("file", "line", "api", "severity")} for c in claims]})
        except httpx.HTTPError as e:
            rows.append({**{k: it[k] for k in ("id", "label", "group")}, "error": str(e)[:120], "wall_s": time.perf_counter() - t})
    ok = [r for r in rows if "error" not in r]
    errors = [r for r in rows if "error" in r]

    def prf(sel):
        mal = [r for r in sel if r["label"] == "malicious"]
        ben = [r for r in sel if r["label"] == "benign"]
        tp = sum(r["flagged"] for r in mal)
        fp = sum(r["flagged"] for r in ben)
        return {"n_malicious": len(mal), "n_benign": len(ben), "tp": tp, "fp": fp, "fn": len(mal) - tp, "tn": len(ben) - fp,
                "precision": tp / (tp + fp) if tp + fp else None, "recall": tp / len(mal) if mal else None,
                "false_positive_rate": fp / len(ben) if ben else None}

    # errors count against recall (an unanswered malicious item is a miss), not silently dropped
    def with_errors(groups):
        sel = [r for r in ok if r["group"] in groups]
        miss = [r for r in errors if r["group"] in groups and r["label"] == "malicious"]
        m = prf(sel)
        m["errors"] = sum(1 for r in errors if r["group"] in groups)
        if miss:
            m["fn"] += len(miss)
            m["n_malicious"] += len(miss)
            m["recall"] = m["tp"] / m["n_malicious"]
        return m

    bait = [r for r in ok if r["group"] == "bait"]
    by_group = {"code (12 malicious / 12 benign)": with_errors({"malicious", "benign"}), "reviewer-bait (6)": with_errors({"bait"}),
                "model cards (3/3)": with_errors({"card"}), "chat templates (2/2)": with_errors({"template"})}
    overall = with_errors({"malicious", "benign", "bait", "card", "template"})
    calls = [r for r in ok if r["llm_calls"]]
    llm_s = sum(r["llm_s"] for r in ok)
    out_tok = sum(r["completion_tokens"] for r in ok)
    per_call_lat = [r["llm_s"] / r["llm_calls"] for r in calls]
    result = {
        "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"), "n_items": len(rows), "n_errors": len(rows) - len(ok),
        "reviewer_llm": httpx.get(url + "/health", timeout=10).json().get("reviewer_llm"),
        "flagged_rule": "verdict in {suspicious, malicious}; an errored request on a malicious item counts as a miss",
        "overall": overall, "by_group": by_group,
        "bait_flagged": sum(r["flagged"] for r in bait) / len(bait) if bait else None,
        "bait_reported_as_claim": sum(r["bait_claim"] for r in bait) / len(bait) if bait else None,
        "latency": {
            "request_wall_s": {"p50": pct([r["wall_s"] for r in ok], .5), "p95": pct([r["wall_s"] for r in ok], .95), "mean": st.mean([r["wall_s"] for r in ok]) if ok else 0},
            "per_llm_call_s": {"p50": pct(per_call_lat, .5), "p95": pct(per_call_lat, .95)},
            "llm_calls_per_request_mean": st.mean([r["llm_calls"] for r in ok]) if ok else 0},
        "tokens": {"prompt": sum(r["prompt_tokens"] for r in ok), "completion": out_tok,
                   "generation_tokens_per_s_incl_prefill": out_tok / llm_s if llm_s else 0.0},
        "total_wall_s": time.time() - t_all, "items": rows,
        "notes": "tokens/sec = completion tokens / LLM wall time (prefill included, structured JSON decoding, batch size 1)."}
    OUT.write_text(json.dumps(result, indent=1))
    return result


if __name__ == "__main__":
    r = run()
    keep = ("n_items", "n_errors", "overall", "by_group", "bait_flagged", "bait_reported_as_claim", "latency", "tokens", "total_wall_s")
    print(json.dumps({k: r[k] for k in keep}, indent=1))
    for x in r["items"]:
        print(f"{x['id']:24s} {x['label']:9s} {x.get('verdict', x.get('error')):10s} claims={x.get('n_claims')} {x.get('max_severity')}")
