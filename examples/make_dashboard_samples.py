"""Sample files for the dashboard's "Load sample" menu: `make_dashboard_samples.py <demo dir> <out dir>`.

`<demo dir>` is what examples/make_demo_hub.py built (the demo stack's WORK/demo). Every sample goes through the real upload path: the page
fetches the file from /samples/<name> and POSTs it to /uploads. All inert (markers only under /tmp/lineage_marker_*, network only 127.0.0.1:9).
"""
from __future__ import annotations

import json
import shutil
import sys
import zipfile
from pathlib import Path

HERE = Path(__file__).parent


def zip_dir(src: Path, dest: Path) -> None:
    with zipfile.ZipFile(dest, "w", zipfile.ZIP_DEFLATED) as z:
        for p in sorted(src.rglob("*")):
            if p.is_file() and p.name not in ("lineage.meta.json", "passport.json") and "__pycache__" not in p.parts:
                z.write(p, p.relative_to(src).as_posix())


def main(demo: Path, out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    up = demo / "uploads"
    zip_dir(demo / "hub" / "models" / "apollo-health" / "triage-base", out / "triage-base.zip")
    shutil.copy(up / "triage-base-tampered.zip", out / "triage-base-tampered.zip")
    shutil.copy(up / "shady-ft.zip", out / "shady-ft.zip")
    shutil.copy(up / "instructions.jsonl", out / "instructions.jsonl")
    shutil.copy(next((demo / "hub" / "pypi" / "acme-llm" / "1.4.1").glob("*.whl")), out / "acme_llm-1.4.1-py3-none-any.whl")
    zip_dir(HERE / "demo_artifacts" / "dicom-fetch", out / "dicom-fetch.zip")
    manifest = [
        {"label": "Clean model (a copy of triage-base)", "file": "triage-base.zip", "name": "triage-base-mirror", "version": "1.0.0", "publisher": "apollo-health", "type": "model", "env": "prod", "claimed_origin": "hf:apollo-health/triage-base",
         "expect": "Every file matches the hub; prod still needs a human approval."},
        {"label": "Tampered copy (one byte changed)", "file": "triage-base-tampered.zip", "name": "triage-base-tampered", "version": "1.0.0", "type": "model", "env": "prod", "claimed_origin": "hf:apollo-health/triage-base",
         "expect": "model.safetensors: changed. Hard block."},
        {"label": "Fine-tune with no claim (hidden template instruction)", "file": "shady-ft.zip", "name": "shady-ft", "version": "0.1.0", "type": "model", "env": "prod",
         "expect": "Trust unknown; the chat template carries a hidden instruction."},
        {"label": "Backdoored instruction dataset", "file": "instructions.jsonl", "name": "instructions-sample", "version": "1.0.0", "type": "dataset", "env": "dev",
         "expect": "5% of rows carry a trigger and an injected link."},
        {"label": "Bad package (acme-llm 1.4.1, startup hook)", "file": "acme_llm-1.4.1-py3-none-any.whl", "type": "package", "env": "prod",
         "expect": "A .pth startup hook that decodes and executes a payload."},
        {"label": "MCP tool (dicom-fetch)", "file": "dicom-fetch.zip", "type": "tool", "env": "dev", "expect": "A tool always needs a human approval."},
    ]
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2))
    # sources the demo hub really serves (the generic examples would answer 404 there)
    presets = [
        {"label": "Model on the hub", "type": "model", "source": "hf:apollo-health/triage-base", "env": "prod"},
        {"label": "Dataset on the hub", "type": "dataset", "source": "hf-dataset:apollo-health/instructions", "env": "dev"},
        {"label": "Package on the index (clean)", "type": "package", "source": "pypi:acme-llm==1.4.0", "env": "prod"},
        {"label": "Package on the index (bad)", "type": "package", "source": "pypi:acme-llm==1.4.1", "env": "prod"},
    ]
    (out / "presets.json").write_text(json.dumps(presets, indent=2))
    print(f"{len(manifest)} samples in {out}")


if __name__ == "__main__":
    main(Path(sys.argv[1]), Path(sys.argv[2]))
