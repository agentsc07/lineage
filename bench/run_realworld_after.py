"""After-refactor false-alarm rate on the real-world sets, static only (no GPU, no key). Presumed-benign real packages and chat templates.

    uv run python -m bench.fetch_realworld /tmp/rw_dev && uv run python -m bench.fetch_final /tmp/rw_final
    uv run python -m bench.make_realworld_sets dev /tmp/rw_dev && uv run python -m bench.make_realworld_sets final /tmp/rw_final
    uv run python -m bench.run_realworld_after            # writes bench/after_refactor_realworld.json

Policy: `unrun_info` (an unrun check costs nothing), like the other static-only columns. The manifests hold absolute paths and are not committed.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from bench import run_ablation as ab  # noqa: E402
from bench.run_after_refactor import policies, run_set  # noqa: E402

SETS = {"PyPI top 1-200 (dev)": "bench/corpus_pypi_top200_dev", "PyPI 201-400 (final)": "bench/corpus_pypi_201_400",
        "HF chat templates (dev, 50)": "bench/corpus_hf_templates", "HF chat templates (final, 50)": "bench/corpus_hf_templates_final"}


def main() -> None:
    out = {}
    only = sys.argv[1:]  # substrings of set names; default all
    for label, path in SETS.items():
        if only and not any(o in label for o in only):
            continue
        if not (ROOT / path / "manifest.json").exists():
            print(f"{label}: manifest missing (not fetched)", file=sys.stderr)
            continue
        rows = run_set(path, "static", policies()["unrun_info"], None)
        flagged = [r for r in rows if r["flagged"] and not r["policy_block"]]
        out[label] = {"n": len(rows), "flagged": len(flagged), "timeouts": sum(bool(r["timeout"]) for r in rows), "errors": sum(bool(r["error"]) and not r["timeout"] for r in rows),
                      "wilson": ab.rates(rows).get("fpr"), "items": [{k: r[k] for k in ("id", "outcome", "risk", "findings", "error")} for r in rows if r["flagged"] or r["error"]]}
        print(f"{label}: {len(flagged)}/{len(rows)} flagged", file=sys.stderr, flush=True)
    dest = ROOT / "bench" / "after_refactor_realworld.json"
    old = json.loads(dest.read_text()) if dest.exists() else {}
    dest.write_text(json.dumps({**old, **out}, indent=2))


if __name__ == "__main__":
    main()
