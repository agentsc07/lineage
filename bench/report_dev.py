"""Render bench/results_dev.md from two bench.run_validation outputs (before / after the precision changes).

    python bench/report_dev.py before.json after.json [bench/results_dev.md]

DEV set = PyPI top 1-200 + 50 HF chat templates + bench/corpus_holdout. Nothing else is read.
"""
from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Why each remaining flag is (or is not) right. Keyed by artifact id; anything flagged but missing here is printed as UNEXPLAINED.
EXPLAIN: dict[str, tuple[str, str]] = {}
if (ROOT / "bench" / "dev_explanations.json").exists():
    EXPLAIN = {k: tuple(v) for k, v in json.loads((ROOT / "bench" / "dev_explanations.json").read_text()).items()}


def pct(x) -> str:
    return "–" if x is None else f"{x:.0%}"


def render(before: dict, after: dict) -> str:
    hb, ha = before["holdout"], after["holdout"]
    L = ["# Dev-set results: before / after the precision changes", "",
         f"Generated {after['generated']} · {after['environment']} · policy `examples/policy.org.yaml` (allow ≤ 30, quarantine ≤ 70, block > 70)", "",
         "**DEV set** = PyPI top 1-200 (wheels), 50 Hugging Face chat templates, `bench/corpus_holdout` (80 items). No other data was read while tuning.",
         "**Flagged** = outcome `block`, or risk above the policy's allow threshold (as in `bench/run_bench.py`). "
         "**Policy block** = blocked only because `allow_pickle: false` forbids the pickle format with nothing dangerous inside; reported separately and not counted as a false positive.",
         "**Before** = branch `precision` at its start (`scanner-fixes` merged). **After** = this branch. PyPI packages are reviewed diff-aware: each is compared with its previous release (fetched wheel-only).", "",
         "## Headline", "",
         "| | before | after |", "|---|---|---|"]
    def rw(d, kind):
        rs = [x for x in d["realworld"]["rows"] if x["kind"] == kind]
        return len(rs), sum(x["flagged"] for x in rs)
    (nb, fb), (na, fa) = rw(before, "package"), rw(after, "package")
    (mb, tb), (ma, ta) = rw(before, "model"), rw(after, "model")
    L += [f"| PyPI top-200 flagged | {fb}/{nb} ({fb / nb:.0%}) | **{fa}/{na} ({fa / na:.0%})** |",
          f"| HF chat templates flagged | {tb}/{mb} ({tb / mb:.0%}) | {ta}/{ma} ({ta / ma:.0%}) |",
          f"| held-out TPR | {pct(hb['overall']['tpr'])} | **{pct(ha['overall']['tpr'])}** |",
          f"| held-out FPR (policy blocks excluded) | {pct(hb['overall']['fpr'])} | {pct(ha['overall']['fpr'])} |",
          f"| held-out policy blocks (pickle, `allow_pickle: false`) | {hb['overall'].get('policy_blocked', 'n/a (counted as FP: 6)')} | {ha['overall'].get('policy_blocked', 0)} |", ""]

    L += ["## Held-out corpus, per category", "",
          "| category | malicious | TPR before | TPR after | benign | FPR before | FPR after | policy blocks |", "|---|---|---|---|---|---|---|---|"]
    for cat, c in sorted(ha["categories"].items()):
        b = hb["categories"].get(cat, {})
        L.append(f"| {cat} | {c['n_malicious']} | {pct(b.get('tpr'))} | **{pct(c['tpr'])}** ({c['tp']}/{c['n_malicious']}) | {c['n_benign']} | {pct(b.get('fpr'))} | {pct(c['fpr'])} | {c.get('policy_blocked', 0)} |")
    L += ["", "Held-out items still wrong after:", ""]
    wrong = [i for i in ha["items"] if (i["label"] == "malicious") != i["positive"] and not i.get("policy_block")]
    L += [f"- `{i['id']}` ({i['label']}): risk {i.get('risk')}, findings {', '.join(i.get('findings', [])) or 'none'}" for i in wrong] or ["- none"]
    L += ["", "Policy blocks (benign pickles refused by `allow_pickle: false`): " + (", ".join(f"`{i['id']}`" for i in ha["items"] if i.get("policy_block")) or "none"), ""]

    L += ["## Real-world false-positive check, per category", "",
          "| set | n | flagged before | flagged after | allow | quarantine | block |", "|---|---|---|---|---|---|---|"]
    for kind, name in (("package", "PyPI top-200"), ("model", "HF chat templates")):
        rb = [x for x in before["realworld"]["rows"] if x["kind"] == kind]
        ra = [x for x in after["realworld"]["rows"] if x["kind"] == kind]
        oc = Counter(x.get("outcome") for x in ra)
        L.append(f"| {name} | {len(ra)} | {sum(x['flagged'] for x in rb)} | **{sum(x['flagged'] for x in ra)}** | {oc['allow']} | {oc['quarantine']} | {oc['block']} |")

    def ids(d, kind):
        c = Counter()
        for x in d["realworld"]["rows"]:
            if x["kind"] == kind and x["flagged"]:
                for i in {f["id"] for f in x["findings"] if f["id"] != "PROV.PUBLISHER.UNLISTED"}:
                    c[i] += 1
        return c
    cb, ca = ids(before, "package"), ids(after, "package")
    L += ["", "### Which findings flagged PyPI packages (items affected)", "", "| finding | before | after |", "|---|---|---|"]
    for k in sorted(set(cb) | set(ca), key=lambda k: (-cb[k], k)):
        L.append(f"| {k} | {cb[k]} | {ca[k]} |")

    flagged = [x for x in after["realworld"]["rows"] if x["flagged"]]
    L += ["", f"## Every remaining flag ({len(flagged)})", "",
          "| artifact | outcome (risk) | findings | verdict |", "|---|---|---|---|"]
    for x in sorted(flagged, key=lambda x: (x["kind"], -x["risk"], x["id"])):
        fids = ", ".join(sorted({f["id"] for f in x["findings"] if f["id"] != "PROV.PUBLISHER.UNLISTED"}))
        v = EXPLAIN.get(x["id"], ("UNEXPLAINED", ""))
        L.append(f"| {x['id']} | {x['outcome']} ({x['risk']}) | {fids} | **{v[0]}**: {v[1]} |")
    names = sorted(x["id"] for x in before["realworld"]["rows"] if x["kind"] == "package" and x["flagged"])
    L += ["", f"<details><summary>The {len(names)} PyPI packages flagged before</summary>", "", ", ".join(names), "", "</details>", ""]
    L += ["## Read this before trusting the numbers", "",
          "- This is now a **dev** set: rules were tuned against it, so 0/200 and 100% TPR are not out-of-sample estimates. The validation commit measured the same held-out corpus at 52% TPR before the `scanner-fixes` merge; `before` here already includes those fixes (75%).",
          "- Diff-aware review lowers anything the previous release already had. A package that shipped its payload in an earlier release is only caught by the combinations that are never lowered (credential exfiltration, fetch-and-run, decoded blob executed, hard advisories), or when the earlier release is itself reviewed.",
          "- With no previous release (first release, offline) only combinations fire; a lone capability such as `subprocess` is a signal. The held-out malicious packages are all first releases, so they test exactly that mode.",
          "- Test code in a wheel is excluded from combinations. The three template flags are `auto_map` custom tokenizer code, kept as quarantine by design.",
          "- Run the real-world half on a fresh sample (PyPI ranks 201-400, other templates) before claiming the rate.", ""]
    errs = [x for x in after["realworld"]["rows"] if "error" in x]
    if errs:
        L += ["Errors: " + "; ".join(f"{x['id']}: {x['error']}" for x in errs), ""]
    return "\n".join(L) + "\n"


if __name__ == "__main__":
    b, a = (json.loads(Path(p).read_text()) for p in sys.argv[1:3])
    out = Path(sys.argv[3]) if len(sys.argv) > 3 else ROOT / "bench" / "results_dev.md"
    out.write_text(render(b, a))
    print("wrote", out)
