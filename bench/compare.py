"""Before/after table for the CPU bench: `python -m bench.compare [--before FILE|git:REF] [--after FILE] [--out FILE]`.

Categories whose items errored in the "after" run (e.g. lora_backdoor when the trained LoRA bank is not on this machine)
are carried over from "before" and marked, never counted as misses.
"""
from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MODE = "dev, no GPU worker"


def load(spec: str) -> dict:
    if spec.startswith("git:"):
        return json.loads(subprocess.run(["git", "show", f"{spec[4:]}:bench/results.json"], cwd=ROOT, check=True,
                                         capture_output=True, text=True).stdout)
    return json.loads(Path(spec).read_text())


def pct(x: float | None) -> str:
    return "–" if x is None else f"{x:.0%}"


def render(before: dict, after: dict) -> str:
    b, a = before["modes"][MODE], after["modes"][MODE]
    rows, carried = [], set()
    cats = {}
    for cat in sorted(b["categories"]):
        old, new = b["categories"][cat], a["categories"].get(cat)
        if new is None or new["errors"]:
            new, _ = old, carried.add(cat)
        cats[cat] = (old, new)
        d = lambda x, y: "–" if x is None or y is None else f"{(y - x) * 100:+.0f} pt"  # noqa: E731
        rows.append(f"| {cat}{' *' if cat in carried else ''} | {old['n_malicious']} / {old['n_benign']} | {pct(old['tpr'])} | {pct(new['tpr'])} | "
                    f"{d(old['tpr'], new['tpr'])} | {pct(old['fpr'])} | {pct(new['fpr'])} | {d(old['fpr'], new['fpr'])} |")

    def overall(side: int) -> tuple[float, float]:
        mal = sum(c[side]["n_malicious"] for c in cats.values())
        ben = sum(c[side]["n_benign"] for c in cats.values())
        return sum(c[side]["tp"] for c in cats.values()) / mal, sum(c[side]["fp"] for c in cats.values()) / ben

    (bt, bf), (at, af) = overall(0), overall(1)
    missed = sorted(i["id"] for i in a["items"] if i["label"] == "malicious" and not i["positive"] and i["category"] not in carried)
    fps = sorted(i["id"] for i in a["items"] if i["label"] == "benign" and i["positive"] and i["category"] not in carried)
    lines = [
        "# LineageBench: before / after scanner fixes", "",
        f"Mode: **{MODE}** (CPU only, `LINEAGE_OFFLINE=1`). Before = `main`'s committed `bench/results.json` ({before['generated']}); "
        f"after = the same corpus and labels re-run on the `scanner-fixes` branch.", "",
        f"| | before | after |", "|---|---|---|",
        f"| overall TPR | {pct(bt)} | {pct(at)} |", f"| overall FPR | {pct(bf)} | {pct(af)} |", "",
        "| category | malicious / benign | TPR before | TPR after | Δ TPR | FPR before | FPR after | Δ FPR |", "|---|---|---|---|---|---|---|---|", *rows, "",
    ]
    if carried:
        lines += [f"\\* {', '.join(sorted(carried))}: not re-run. The trained LoRA bank (`bank/`) is not in the repo, so the "
                  "after-run errored on every item; the *before* numbers are carried over rather than counted as misses. "
                  "This category is GPU-worker calibration and was deliberately left alone.", ""]
    lines += [f"Still missed (after, re-run categories): {', '.join(missed) or 'none'}", f"False positives (after, re-run categories): {', '.join(fps) or 'none'}", ""]
    return "\n".join(lines)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--before", default="git:main")
    ap.add_argument("--after", default=str(ROOT / "bench" / "results.json"))
    ap.add_argument("--out", default=str(ROOT / "bench" / "results_before_after.md"))
    args = ap.parse_args()
    Path(args.out).write_text(render(load(args.before), load(args.after)))
    print(Path(args.out).read_text())
