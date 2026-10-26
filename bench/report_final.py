"""Render bench/results_final.md (+ .json) from the final run's outputs (Track D). Computes; never thresholds or tunes.

Inputs: bench/ablation.json (run_ablation), bench/results.json (run_bench, with worker), bench/weightspace.json (calibration),
optional bench/final_reasons.json {item id: one-line reason} written by hand after reading the lists, bench/cost_log.csv.

Columns: in-sample = bench/corpus (the system was built against it); dev = bench/corpus_holdout + PyPI top 1-200 + 50 dev HF templates
(the other tracks tuned on them); FINAL unseen = bench/corpus_final + PyPI 201-400 + 50 new HF templates (nothing tuned after seeing them).
Numbers are the full system (static + reviewer, worker on) unless a row says "static only".
"""
from __future__ import annotations

import csv
import json
import random
import statistics
from datetime import datetime, timezone
from pathlib import Path

from bench.report import _wilson

ROOT = Path(__file__).resolve().parent.parent
USD_PER_HOUR = 1.74
COLS = {
    "in-sample (bench/corpus)": {"synthetic": ["corpus"], "pypi": [], "templates": []},
    "dev (tuned on)": {"synthetic": ["corpus_holdout"], "pypi": ["pypi_top200_dev"], "templates": ["hf_templates"]},
    "FINAL unseen": {"synthetic": ["corpus_final"], "pypi": ["pypi_201_400"], "templates": ["hf_templates_final"]},
}


def pct(x) -> str:
    return "n/a" if x is None else f"{x:.0%}"


def frac(k: int, n: int) -> str:
    if n == 0:
        return "n/a"
    lo, hi = _wilson(k, n)
    return f"{k / n:.0%} ({k}/{n}; 95% CI {lo:.0%}–{hi:.0%})"


def q(xs: list[float], p: float) -> float:
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(p * len(xs)))] if xs else 0.0


def rows_of(ab: dict, names: list[str], mode: str) -> list[dict]:
    out = []
    for n in names:
        s = ab["sets"].get(n)
        if s and s.get("status") == "ran":
            out += s["items"][mode]
    return out


def tpr_fpr(rows: list[dict]) -> dict:
    mal = [r for r in rows if r["label"] == "malicious"]
    ben = [r for r in rows if r["label"] == "benign"]
    pb = [r for r in ben if r["flagged"] and r.get("policy_block")]
    fp = [r for r in ben if r["flagged"] and not r.get("policy_block")]
    return {"tp": sum(r["flagged"] for r in mal), "n_mal": len(mal), "fp": len(fp), "n_ben": len(ben), "policy_blocked": len(pb),
            "timeouts": sum(1 for r in rows if r.get("timeout"))}


def auroc_ci(pos: list[float], neg: list[float], n: int = 2000, seed: int = 0) -> tuple[float, float, float]:
    def auc(p, m):
        return sum((a > b) + 0.5 * (a == b) for a in p for b in m) / (len(p) * len(m))
    rng = random.Random(seed)
    vals = sorted(auc([rng.choice(pos) for _ in pos], [rng.choice(neg) for _ in neg]) for _ in range(n))
    return auc(pos, neg), vals[int(0.025 * n)], vals[int(0.975 * n)]


def main() -> None:
    ab = json.loads((ROOT / "bench" / "ablation.json").read_text())
    br = json.loads((ROOT / "bench" / "results.json").read_text())
    ws = json.loads((ROOT / "bench" / "weightspace.json").read_text())
    reasons_f = ROOT / "bench" / "final_reasons.json"
    reasons = json.loads(reasons_f.read_text()) if reasons_f.exists() else {}
    gpu_mode = next(k for k in br["modes"] if "with GPU worker" in k)
    lora_items = [i for i in br["modes"][gpu_mode]["items"] if i["category"] == "lora_backdoor"]
    lo_auc = auroc_ci([i["score"] for i in lora_items if i["label"] == "malicious"], [i["score"] for i in lora_items if i["label"] == "benign"])

    R: dict = {"generated": datetime.now(timezone.utc).isoformat(timespec="seconds"), "columns": {}}
    for col, spec in COLS.items():
        syn_names, pypi, tpl = spec["synthetic"], spec["pypi"], spec["templates"]
        c: dict = {}
        for mode, key in (("reviewer", "full"), ("static", "static")):
            c[f"synthetic_{key}"] = tpr_fpr(rows_of(ab, syn_names, mode))
        real_p = rows_of(ab, pypi, "reviewer")
        real_p_s = rows_of(ab, pypi, "static")
        real_t = rows_of(ab, tpl, "reviewer")
        real_t_s = rows_of(ab, tpl, "static")
        c["pypi"] = {"flagged": sum(r["flagged"] for r in real_p), "n": len(real_p), "static_flagged": sum(r["flagged"] for r in real_p_s),
                     "timeouts": sum(1 for r in real_p if r.get("timeout"))}
        c["templates"] = {"flagged": sum(r["flagged"] for r in real_t), "n": len(real_t), "static_flagged": sum(r["flagged"] for r in real_t_s),
                          "timeouts": sum(1 for r in real_t if r.get("timeout"))}
        # reviewer-changed decisions across the whole column
        ch = {"tp_gained": [], "fp_introduced": [], "tp_lost": [], "fp_removed": [], "outcome_only": [], "called": 0, "n_intake": 0}
        sets = syn_names + pypi + tpl
        for n in sets:
            s = ab["sets"].get(n)
            if not s or s.get("status") != "ran":
                continue
            ch["called"] += s["cost"]["n_reviewed"]
            ch["n_intake"] += s["cost"]["n_intake_items"]
            for e in s["changes"]["raised_to_flagged"]:
                ch["tp_gained" if e["label"] == "malicious" else "fp_introduced"].append(e["id"])
            for e in s["changes"]["lowered_to_unflagged"]:
                ch["tp_lost" if e["label"] == "malicious" else "fp_removed"].append(e["id"])
            ch["outcome_only"] += [e["id"] for e in s["changes"]["outcome_changed_same_flag"]]
        c["changes"] = ch
        intake_s = [r["seconds"] for n in sets for r in (ab["sets"].get(n, {}).get("items", {}).get("static", [])) if r["check"] == "intake"]
        intake_r = [r["seconds"] for n in sets for r in (ab["sets"].get(n, {}).get("items", {}).get("reviewer", [])) if r["check"] == "intake"]
        real_s = [r["seconds"] for r in real_p_s + real_t_s]
        real_r = [r["seconds"] for r in real_p + real_t]
        c["latency"] = {"static": [q(intake_s, .5), q(intake_s, .95)], "reviewer": [q(intake_r, .5), q(intake_r, .95)],
                        "real_static": [q(real_s, .5), q(real_s, .95)], "real_reviewer": [q(real_r, .5), q(real_r, .95)]}
        gpu_s = sum(ab["sets"][n]["cost"]["gpu_seconds_total"] for n in sets if ab["sets"].get(n, {}).get("status") == "ran")
        n_art = sum(ab["sets"][n]["n_items"] for n in sets if ab["sets"].get(n, {}).get("status") == "ran")
        wall = sum(r["seconds"] for n in sets for r in ab["sets"].get(n, {}).get("items", {}).get("reviewer", []) if r["check"] == "intake")
        c["cost"] = {"n_artifacts": n_art, "gpu_seconds": gpu_s, "gpu_s_per_artifact": gpu_s / n_art if n_art else 0.0,
                     "usd_busy_per_artifact": gpu_s / n_art / 3600 * USD_PER_HOUR if n_art else 0.0,
                     "usd_wall_per_artifact": wall / n_art / 3600 * USD_PER_HOUR if n_art else 0.0}
        R["columns"][col] = c
    R["lora"] = {"in_sample": {"auroc": lo_auc[0], "ci95": lo_auc[1:], "n_mal": sum(i["label"] == "malicious" for i in lora_items),
                               "n_ben": sum(i["label"] == "benign" for i in lora_items)},
                 "dev": {"auroc": ws["test"]["auroc"], "ci95": ws["test"]["ci95"], "n_test": ws["n_test"], "n_excluded_low_asr": ws["n_excluded_low_asr"]}}

    cols = list(COLS)
    ci_ = R["columns"]
    hdr = "| | " + " | ".join(f"**{c}**" for c in cols) + " |"
    L = ["# Final results", "",
         f"Generated {R['generated']} · full system = static scanners + GPU worker (reviewer LLM `{ab['reviewer_llm']}` and the worker's other deep checks) unless a row says *static only* · "
         "flagged = outcome `block` or risk above the allow threshold (30) · benign pickles refused only by `allow_pickle: false` are *policy blocks*, listed separately and not counted as false positives.", "",
         "**Columns.** *in-sample* = `bench/corpus` (the system was built against it). *dev (tuned on)* = `bench/corpus_holdout` + PyPI top 1-200 + 50 HF chat templates (other tracks tuned scanner rules on them). "
         "**FINAL unseen** = `bench/corpus_final` (40 malicious + 40 benign) + PyPI ranks 201-400 + 50 further HF chat templates, built/fetched after the code was frozen; nothing was tuned after seeing them. "
         "PyPI packages and HF templates are *presumed* benign: their rates are false-alarm rates, not FPR against verified-clean data.", "",
         "## Headline", "", hdr, "|---|" + "---|" * len(cols)]

    def row(label, fn):
        L.append(f"| {label} | " + " | ".join(fn(ci_[c], c) for c in cols) + " |")

    row("TPR on malicious items (full system)", lambda c, _: frac(c["synthetic_full"]["tp"], c["synthetic_full"]["n_mal"]))
    row("TPR (static only)", lambda c, _: frac(c["synthetic_static"]["tp"], c["synthetic_static"]["n_mal"]))
    row("FPR on benign items (full system, policy blocks excluded)", lambda c, _: frac(c["synthetic_full"]["fp"], c["synthetic_full"]["n_ben"]))
    row("FPR (static only)", lambda c, _: frac(c["synthetic_static"]["fp"], c["synthetic_static"]["n_ben"]))
    row("Intake timeouts (no decision in 120 s; not counted as flagged)", lambda c, _: str(c["synthetic_full"]["timeouts"] + c["pypi"]["timeouts"] + c["templates"]["timeouts"]))
    row("Policy blocks among benign (pickle format)", lambda c, _: str(c["synthetic_full"]["policy_blocked"]))
    row("Real-package false-alarm rate (PyPI wheels, full system)", lambda c, _: frac(c["pypi"]["flagged"], c["pypi"]["n"]) if c["pypi"]["n"] else "n/a (none in this column)")
    row("Real-package false-alarm rate (static only)", lambda c, _: frac(c["pypi"]["static_flagged"], c["pypi"]["n"]) if c["pypi"]["n"] else "n/a")
    row("HF chat templates flagged (full system)", lambda c, _: f"{c['templates']['flagged']}/{c['templates']['n']}" if c["templates"]["n"] else "n/a")
    row("HF chat templates flagged (static only)", lambda c, _: f"{c['templates']['static_flagged']}/{c['templates']['n']}" if c["templates"]["n"] else "n/a")

    def chg(c, _):
        h = c["changes"]
        up = f"+{len(h['tp_gained']) + len(h['fp_introduced'])} flagged ({len(h['tp_gained'])} true positives gained, {len(h['fp_introduced'])} false alarms introduced)"
        dn = f"−{len(h['tp_lost']) + len(h['fp_removed'])} unflagged ({len(h['tp_lost'])} true positives lost, {len(h['fp_removed'])} false alarms removed)"
        return f"{up}; {dn}; {len(h['outcome_only'])} outcome-only; reviewer called on {h['called']}/{h['n_intake']} intake items"
    row("Decisions changed by the worker/reviewer (static → full)", chg)
    row("LoRA backdoor detector AUROC", lambda c, col: (
        f"{R['lora']['in_sample']['auroc']:.2f} (CI {R['lora']['in_sample']['ci95'][0]:.2f}–{R['lora']['in_sample']['ci95'][1]:.2f}; {R['lora']['in_sample']['n_mal']} backdoored / {R['lora']['in_sample']['n_ben']} benign adapters, held-out test split)"
        if col.startswith("in-sample") else
        f"{R['lora']['dev']['auroc']:.2f} (CI {R['lora']['dev']['ci95'][0]:.2f}–{R['lora']['dev']['ci95'][1]:.2f}; n={R['lora']['dev']['n_test']} held-out adapters; recipe/lr tuned on this bank)"
        if col.startswith("dev") else "not measured: no unseen adapters were trained"))
    row("Intake latency p50 / p95, all items: static → full", lambda c, _: (f"{c['latency']['static'][0] * 1000:.0f} / {c['latency']['static'][1] * 1000:.0f} ms → "
                                                                           f"{c['latency']['reviewer'][0] * 1000:.0f} / {c['latency']['reviewer'][1] * 1000:.0f} ms"))
    row("Intake latency p50 / p95, real PyPI+templates only: static → full", lambda c, _: (
        f"{c['latency']['real_static'][0] * 1000:.0f} / {c['latency']['real_static'][1] * 1000:.0f} ms → {c['latency']['real_reviewer'][0] * 1000:.0f} / {c['latency']['real_reviewer'][1] * 1000:.0f} ms"
        if c["pypi"]["n"] or c["templates"]["n"] else "n/a"))
    row(f"GPU seconds per artifact (reviewer LLM busy time)", lambda c, _: f"{c['cost']['gpu_s_per_artifact']:.2f} s over {c['cost']['n_artifacts']} artifacts")
    row(f"Cost per artifact at ${USD_PER_HOUR}/h, busy time only", lambda c, _: f"${c['cost']['usd_busy_per_artifact']:.5f}")
    row(f"Cost per artifact at ${USD_PER_HOUR}/h, whole intake wall time", lambda c, _: f"${c['cost']['usd_wall_per_artifact']:.5f}")

    # --- every final-set miss / false alarm
    fin = COLS["FINAL unseen"]
    L += ["", "## Every FINAL-set miss and false alarm", ""]

    def reason(r):
        return reasons.get(r["id"], "(reason not written)")
    for title, names, want in (("Missed malicious (corpus_final, full system)", fin["synthetic"], "miss"),
                               ("False alarms on benign (corpus_final, full system, excluding policy blocks)", fin["synthetic"], "fa"),
                               ("False alarms among real PyPI 201-400 packages", fin["pypi"], "fa"),
                               ("HF chat templates flagged (final set)", fin["templates"], "fa")):
        rs = rows_of(ab, names, "reviewer")
        st = {r["id"]: r for r in rows_of(ab, names, "static")}
        bad = [r for r in rs if (r["label"] == "malicious" and not r["flagged"])] if want == "miss" else \
              [r for r in rs if r["label"] == "benign" and r["flagged"] and not r.get("policy_block")]
        L.append(f"**{title}: {len(bad)}**")
        for r in bad:
            s = st.get(r["id"], {})
            L.append(f"- `{r['id']}` — {r['outcome']}, risk {r['risk']} (static only: {s.get('outcome')}, risk {s.get('risk')}); findings {', '.join(r.get('findings') or []) or 'none'} — {reason(r)}")
        L.append("")
    tos = [r for n in fin["synthetic"] + fin["pypi"] + fin["templates"] for r in rows_of(ab, [n], "reviewer") if r.get("timeout")]
    L.append(f"**Intake timeouts on the final sets (the pipeline did not finish within 120 s, so there is no decision): {len(tos)}**")
    for r in tos:
        L.append(f"- `{r['id']}` — {reasons.get(r['id'], '(reason not written)')}")
    L.append("")
    pbs = [r for r in rows_of(ab, fin["synthetic"], "reviewer") if r["label"] == "benign" and r.get("policy_block") and r["flagged"]]
    L.append(f"**Policy blocks (benign pickles refused by `allow_pickle: false`): {len(pbs)}** " + ", ".join(f"`{r['id']}`" for r in pbs))
    ch = R["columns"]["FINAL unseen"]["changes"]
    L += ["", "**Final-set decisions changed by the reviewer/worker** — true positives gained: " + (", ".join(f"`{i}`" for i in ch["tp_gained"]) or "none")
          + " · false alarms introduced: " + (", ".join(f"`{i}`" for i in ch["fp_introduced"]) or "none")
          + " · true positives lost: " + (", ".join(f"`{i}`" for i in ch["tp_lost"]) or "none")
          + " · false alarms removed: " + (", ".join(f"`{i}`" for i in ch["fp_removed"]) or "none")
          + " · outcome-only: " + (", ".join(f"`{i}`" for i in ch["outcome_only"]) or "none"), ""]

    # --- caveats
    L += ["## Read this before quoting a number", "",
          "- The final synthetic corpus is **my own construction** (80 items, 6 categories): it tests generalisation to new techniques, not to adversaries who know the scanners. Intervals are wide; treat differences of a few items as noise.",
          "- Real PyPI/HF artifacts are presumed benign. A flagged real package may be a true finding; each is listed above with the reason.",
          "- The dev real-world sets were re-fetched here (top-PyPI snapshot 2026-10-01, HF `main` today), so they match the other session's procedure but not necessarily its exact bytes.",
          "- LoRA detector: the only 'unseen' LoRA data would require training new adapters; none were trained for this run, so the final column has no LoRA number. The in-sample and dev numbers use the same held-out test split of one bank whose training recipe was tuned.",
          "- Cost rows: 'busy time' is the reviewer LLM's wall time on a dedicated GPU; 'whole intake wall time' charges the GPU for the entire time an artifact is in intake. Weight-space and behaviour checks are not in these figures.",
          f"- Reviewer unit benchmark (separate, small, partly tuned): see `bench/reviewer.json` and the Reviewer section of `bench/results.md`.", ""]
    (ROOT / "bench" / "results_final.md").write_text("\n".join(L))
    (ROOT / "bench" / "results_final.json").write_text(json.dumps(R, indent=1, default=str))
    print("wrote bench/results_final.md")


if __name__ == "__main__":
    main()
