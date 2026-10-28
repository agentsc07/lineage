"""Validation run: held-out corpus + real-world false-positive check, through the same pipeline as run_bench (dev, CPU).

    python -m bench.run_validation <realworld_dir>     # realworld_dir from bench/fetch_realworld.py (outside the repo)

Writes bench/results_holdout.json; bench/report_holdout.py renders bench/results_holdout.md from it.
"""
from __future__ import annotations

import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from bench.run_bench import NO_WORKER, NOW, ROOT, run_mode
from tests.fixtures.builders import make_tiny_model, make_tokenizer_dir

OLD = "2025-01-01T00:00:00Z"


def _prepare_realworld(rw: Path) -> list[dict]:
    """Give each downloaded artifact the sidecar metadata run_bench items have. Everything outside the repo."""
    items = []
    prev = json.loads((rw / "previous.json").read_text()) if (rw / "previous.json").exists() else {}
    for d in sorted((rw / "packages").iterdir()):
        meta = {"released_at": OLD, "licence": "mit", "repo": f"pypi/{d.name}", "name": d.name}
        p = prev.get(d.name) or {}
        if p.get("previous") and (rw / "previous" / d.name).is_dir():  # baseline for diff-aware review
            meta.update(version=p["version"], previous_path=str(rw / "previous" / d.name), previous_version=p["previous"])
        (d / "lineage.meta.json").write_text(json.dumps(meta))
        items.append({"id": d.name, "kind": "package", "path": str(d)})
    for d in sorted((rw / "templates").iterdir()):
        cfg = json.loads((d / "tokenizer_config.json").read_text())
        make_tiny_model(d, seed=7)
        make_tokenizer_dir(d)  # writes a stub tokenizer.json + tokenizer_config.json ...
        (d / "tokenizer_config.json").write_text(json.dumps(cfg))  # ... then restore the real config with its template
        (d / "lineage.meta.json").write_text(json.dumps({"released_at": OLD, "licence": "mit", "repo": f"hf/{d.name}", "name": d.name}))
        items.append({"id": d.name, "kind": "model", "path": str(d)})
    return items


def run_realworld(rw: Path, policy) -> list[dict]:
    from lineage.intake.pipeline import run_to_decision
    rows = []
    for it in _prepare_realworld(rw):
        t0 = time.perf_counter()
        try:
            from bench.meta_hub import MetaFileHub
            d, _ = run_to_decision(it["kind"], it["path"], "dev", policy, "bench", gpu_url=NO_WORKER, now=NOW, hub=MetaFileHub(it["path"]))
            flagged = d.outcome == "block" or d.risk_score > policy.thresholds.allow
            fs = [{"id": f.id, "severity": f.severity, "title": f.title, "score": f.score, "source": f.source,
                   "evidence": [f"{e.ref}" + (f" ({e.detail})" if e.detail else "") for e in f.evidence[:3]]}
                  for f in d.findings if f.severity != "info"]
            rows.append({"id": it["id"], "kind": it["kind"], "flagged": flagged, "outcome": d.outcome, "risk": d.risk_score,
                         "reasons": d.reasons[:3], "info": sorted({f.id for f in d.findings if f.severity == "info"}),
                         "findings": fs if flagged else [], "n_findings": len(fs), "seconds": round(time.perf_counter() - t0, 3)})
        except Exception as e:  # noqa: BLE001 - record, never abort
            rows.append({"id": it["id"], "kind": it["kind"], "flagged": False, "error": f"{type(e).__name__}: {e}"[:300],
                         "seconds": round(time.perf_counter() - t0, 3)})
        print(f"{it['kind']:8s} {it['id'][:50]:50s} {'FLAG' if rows[-1].get('flagged') else 'ok  '} {rows[-1].get('error', '')}", flush=True)
    return rows


def main(rw: Path, out: Path | None = None) -> None:
    from lineage.schemas.policy import PolicyPack
    policy = PolicyPack.from_yaml(ROOT / "examples" / "policy.org.yaml")
    hold = run_mode(ROOT / "bench" / "corpus_holdout", policy, NO_WORKER, "dev")
    fetch = json.loads((rw / "fetch.json").read_text())
    real = run_realworld(rw, policy)
    (out or ROOT / "bench" / "results_holdout.json").write_text(json.dumps({
        "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"), "environment": "dev, CPU, no GPU worker, LINEAGE_OFFLINE=1",
        "holdout": hold, "realworld": {"fetch": fetch, "rows": real}}, indent=1))
    print("holdout overall", hold["overall"])


if __name__ == "__main__":
    main(Path(sys.argv[1]), Path(sys.argv[2]) if len(sys.argv) > 2 else None)
