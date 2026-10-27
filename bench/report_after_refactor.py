"""Write bench/results_after_refactor.md: after-refactor numbers next to the frozen final numbers (never overwrites results_final.md)."""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
COLS = {"in-sample (bench/corpus)": "in-sample (bench/corpus)", "dev (bench/corpus_holdout)": "dev (tuned on)", "FINAL synthetic (bench/corpus_final)": "FINAL unseen"}


def wilson(k: int, n: int) -> tuple[float, float]:
    if not n:
        return 0.0, 0.0
    z, p = 1.96, k / n
    d = 1 + z * z / n
    c = p + z * z / (2 * n)
    m = z * ((p * (1 - p) / n + z * z / (4 * n * n)) ** 0.5)
    return (c - m) / d, (c + m) / d


def cell(k: int, n: int) -> str:
    lo, hi = wilson(k, n)
    return f"{100 * k / n:.0f}% ({k}/{n}; {100 * lo:.0f}-{100 * hi:.0f}%)" if n else "n/a"


def rates(block: dict) -> tuple[str, str]:
    r = block["rates"]
    return cell(r["tp"], r["n_malicious"]), cell(r["fp"], r["n_benign"])


def main() -> None:
    frozen = json.loads((ROOT / "bench" / "results_final.json").read_text())["columns"]
    out = {}
    for mode in ("static", "hosted"):
        f = ROOT / "bench" / f"after_refactor_{mode}.json"
        out[mode] = json.loads(f.read_text()) if f.is_file() else None
    L = ["# After-refactor results", "",
         f"Static-only generated {out['static']['generated'] if out['static'] else 'not run'}; reviewer-through-the-hosted-API generated "
         f"{out['hosted']['generated'] if out['hosted'] else 'NOT RUN (see below)'}. The frozen numbers are `bench/results_final.md` (never overwritten).", "",
         "## Read this first", "",
         "- **After-refactor numbers were measured on sets the fixes were written with knowledge of** (the detection rules for atexit, import hooks, reversed names, git hooks, "
         "beacons, hidden tool calls, zero-width directives and tool-output scanning were written after the final-set misses were known). They are not unseen-data numbers; "
         "the frozen FINAL column is the only unseen measurement.",
         "- **Only the in-repo synthetic sets were re-run.** The real-world sets (PyPI top 200 and 201-400, 100 HF templates) are not on this machine (their manifests point "
         "to `/home/ubuntu/...`), so their false-alarm rates are not re-measured; the frozen values stay in `results_final.md`. The taint hang was re-checked on the real "
         "`black`, `datasets` and `kubernetes` wheels instead (below).",
         "- **The frozen run's 'full system' used the Brev GPU worker** (reviewer `nvidia/NVIDIA-Nemotron-Nano-9B-v2` on vLLM plus weight/behaviour checks). The hosted API does not list that model, "
         f"so this run's reviewer is `{(out['hosted'] or {}).get('model') or 'nvidia/nemotron-3.5-lightning-30b-a3b (not run)'}`, a different and larger model, in precise mode. "
         "**Reviewer numbers are not directly comparable with the frozen run**, and there is no GPU, so weight, behaviour and Notary checks are `CHECK.NOT_RUN.*` here.",
         "- **The LoRA weight-space items are not re-run** (they need the trained adapter bank and torch, neither on this machine): the in-sample column's frozen figures include "
         "20 malicious and 20 benign LoRA items that the after-refactor columns leave out (the frozen LoRA AUROC, 0.81 / 0.78, is unchanged since no weight-space code changed). "
         "The `bind` items use passports re-issued in the new format (`bench/refresh_bind.py`); the tamper check is the old passport-hash one, kept for the benchmark.",
         "- Two policies per run: *as shipped* prices every unrun check (a model without the GPU checks carries risk in staging) and *unrun = info* prices them at 0 so the detectors can be "
         "compared with the frozen run, where those checks were simply absent. Flagged = `block` or risk above 30 (staging), as before.", ""]
    L += ["## Detection on the synthetic sets", "",
          "| set | frozen full system (Brev worker) | frozen static only | after: static only, unrun = info | after: static only, as shipped | after: hosted reviewer, unrun = info | after: hosted reviewer, as shipped |",
          "|---|---|---|---|---|---|---|"]
    for label, fcol in COLS.items():
        fr = frozen[fcol]
        def fz(k):
            x = fr[k]
            return cell(x["tp"], x["n_mal"]) + " / FPR " + cell(x["fp"], x["n_ben"])
        row = [f"**{label}**", "TPR " + fz("synthetic_full"), "TPR " + fz("synthetic_static")]
        for mode, pol in (("static", "unrun_info"), ("static", "as_shipped"), ("hosted", "unrun_info"), ("hosted", "as_shipped")):
            b = (out[mode] or {}).get("sets", {}).get(label, {}).get(pol)
            row.append("not run" if b is None else "TPR " + rates(b)[0] + " / FPR " + rates(b)[1])
        L.append("| " + " | ".join(row) + " |")
    L += ["", "Frozen TPR/FPR cells are `TPR x (tp/n) / FPR y (fp/n)`; intervals are Wilson 95%. Benign pickles refused only by `allow_pickle: false` are policy blocks and excluded from FPR in every column.", ""]
    for mode, title in (("static", "Static only"), ("hosted", "Reviewer through the hosted API")):
        o = out[mode]
        if not o:
            L += [f"## {title}", "", "Not run.", ""]
            continue
        L += [f"## {title}: latency and reviewer cost", "", "| set (unrun = info) | intake p50 / p95 | timeouts | errors | reviewer calls | reviewer wall s | reviewer tokens |", "|---|---|---|---|---|---|---|"]
        for label, per in o["sets"].items():
            b = per.get("unrun_info")
            if b:
                rows = b["rows"]
                L.append(f"| {label} | {b['p50_ms']:.0f} / {b['p95_ms']:.0f} ms | {b['rates']['timeouts']} | {b['rates']['errors']} | {sum(r['reviewer_calls'] for r in rows)} | "
                         f"{sum(r['reviewer_s'] for r in rows):.0f} | {sum(r['reviewer_tokens'] for r in rows):,} |")
        L.append("")
    if out["static"]:
        L += ["## Every miss and false alarm on the FINAL synthetic set (static only, unrun = info)", ""]
        b = out["static"]["sets"].get("FINAL synthetic (bench/corpus_final)", {}).get("unrun_info")
        if b:
            miss = [r for r in b["rows"] if r["label"] == "malicious" and not r["flagged"]]
            fa = [r for r in b["rows"] if r["label"] == "benign" and r["flagged"] and not r["policy_block"]]
            L += [f"**Missed malicious: {len(miss)}**"] + [f"- `{r['id']}`: {r['outcome']}, risk {r['risk']}; {', '.join(r['findings'] or [])}" for r in miss]
            L += ["", f"**False alarms: {len(fa)}**"] + [f"- `{r['id']}`: {r['outcome']}, risk {r['risk']}; {', '.join(r['findings'] or [])}" for r in fa] + [""]
    if out["static"] and out["hosted"]:
        L += ["## What the hosted reviewer changed (same policy: unrun = info)", ""]
        for label in COLS:
            s = out["static"]["sets"].get(label, {}).get("unrun_info")
            h = out["hosted"]["sets"].get(label, {}).get("unrun_info")
            if not (s and h):
                continue
            up = [(a["id"], a["label"]) for a, b in zip(s["rows"], h["rows"]) if not a["flagged"] and b["flagged"]]
            down = [(a["id"], a["label"]) for a, b in zip(s["rows"], h["rows"]) if a["flagged"] and not b["flagged"]]
            L += [f"- **{label}**: newly flagged {len(up)} ({sum(1 for _, l in up if l == 'malicious')} malicious, {sum(1 for _, l in up if l == 'benign')} benign); unflagged {len(down)}. "
                  + (", ".join(f"`{i}` ({l})" for i, l in up[:8]) if up else "")]
        L.append("")
    pr = ROOT / "bench" / "taint_recheck.md"
    if pr.is_file():
        L += ["## Taint hang re-check on real wheels", "", pr.read_text(), ""]
    (ROOT / "bench" / "results_after_refactor.md").write_text("\n".join(L) + "\n")
    print("\n".join(L))


if __name__ == "__main__":
    main()
