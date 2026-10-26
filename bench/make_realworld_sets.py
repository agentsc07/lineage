"""Turn fetched real-world directories (bench/fetch_realworld.py, bench/fetch_final.py; outside the repo) into manifest sets for run_ablation.

    uv run python -m bench.make_realworld_sets dev   /home/ubuntu/rw_dev    # -> bench/corpus_pypi_top200_dev, bench/corpus_hf_templates
    uv run python -m bench.make_realworld_sets final /home/ubuntu/rw_final  # -> bench/corpus_pypi_201_400, bench/corpus_hf_templates_final

Each manifest lists absolute paths (the artifacts are never copied into the repo). Everything is labelled benign: these are presumed-benign
real packages and templates, so the numbers they give are false-alarm rates, not FPR against verified-clean data.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from bench.run_validation import _prepare_realworld

ROOT = Path(__file__).resolve().parent.parent
TARGETS = {"dev": ("corpus_pypi_top200_dev", "corpus_hf_templates"), "final": ("corpus_pypi_201_400", "corpus_hf_templates_final")}


def main(which: str, rw: Path) -> None:
    pkg_set, tpl_set = TARGETS[which]
    items = _prepare_realworld(rw)  # writes lineage.meta.json (+ tiny models for templates) next to each artifact, outside the repo
    fetch = json.loads((rw / "fetch.json").read_text())
    for name, kind, cat in ((pkg_set, "package", "real_pypi"), (tpl_set, "model", "real_template")):
        rows = [{"id": i["id"], "category": cat, "label": "benign", "kind": kind, "check": "intake", "path": i["path"]} for i in items if i["kind"] == kind]
        out = ROOT / "bench" / name
        out.mkdir(exist_ok=True)
        (out / "manifest.json").write_text(json.dumps({"n_lora": 0, "source": str(rw), "top_list_updated": fetch.get("top_list_updated"),
                                                      "note": "absolute paths to artifacts outside the repo; presumed benign", "items": rows}, indent=1))
        print(name, len(rows))


if __name__ == "__main__":
    main(sys.argv[1], Path(sys.argv[2]))
