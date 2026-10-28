"""Build everything demo v2 needs besides the server: a fake hub tree, its records, and the files an uploader would send.

    uv run python examples/make_demo_hub.py <out dir>

<out>/hub/models/apollo-health/triage-base/      the base model Lineage will fetch from the hub
<out>/hub/datasets/apollo-health/instructions/   a clean instruction set (the upstream)
<out>/hub/pypi/acme-llm/{1.4.0,1.4.1}/        a clean wheel and one with a start-up (.pth) hook; <out>/hub/pypi/tokenizers-fast/0.9.2/
<out>/hub.json                                 hub records (release dates, licences): what the hub says is `fetched`
<out>/uploads/                                 triage-base-tampered.zip, shady-ft.zip (no claim), instructions.jsonl (5% backdoor)
Everything is inert: payloads only name /tmp/lineage_marker_* and the closed port 127.0.0.1:9.
"""
from __future__ import annotations

import base64
import json
import random
import shutil
import sys
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))

import make_demo_artifacts as art  # noqa: E402
from bench import data_bench as db  # noqa: E402

OLD = "2026-01-10T00:00:00Z"


def wheel(path: Path, name: str, version: str, files: dict[str, str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w") as z:
        for n, c in files.items():
            z.writestr(n, c)
        z.writestr(f"{name}-{version}.dist-info/METADATA", f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\nSummary: demo package\n")
        z.writestr(f"{name}-{version}.dist-info/WHEEL", "Wheel-Version: 1.0\nGenerator: demo\nRoot-Is-Purelib: true\nTag: py3-none-any\n")
        z.writestr(f"{name}-{version}.dist-info/RECORD", "")


def zip_dir(src: Path, dest: Path, skip=("lineage.meta.json", "passport.json")) -> None:
    with zipfile.ZipFile(dest, "w") as z:
        for p in sorted(src.rglob("*")):
            if p.is_file() and p.name not in skip:
                z.write(p, p.relative_to(src).as_posix())


def main(out: Path) -> None:
    if out.exists():
        shutil.rmtree(out)
    hub, up = out / "hub", out / "uploads"
    base = hub / "models" / "apollo-health" / "triage-base"
    art.write_model(base, art.model_tensors(), art.CLEAN_TEMPLATE, "---\nlicense: apache-2.0\n---\n# triage-base\nTiny stand-in for Apollo's radiology triage model.\n")
    # uploads: a one-byte tamper of the fetched model, and the fine-tune with a hidden template instruction (no claim)
    tampered = out / "tampered"
    shutil.copytree(base, tampered)
    w = tampered / "model.safetensors"
    b = bytearray(w.read_bytes())
    b[-1] ^= 0xFF
    w.write_bytes(bytes(b))
    up.mkdir(parents=True)
    zip_dir(tampered, up / "triage-base-tampered.zip")
    shutil.rmtree(tampered)
    child = out / "shady"
    base_t = art.model_tensors()
    import numpy as np

    rng = np.random.default_rng(99)
    ft = dict(base_t)
    for i in art.CHANGED:
        wt = base_t[f"layers.{i}.weight"]
        ft[f"layers.{i}.weight"] = (wt + 0.05 * np.linalg.norm(wt) / np.sqrt(wt.size) * rng.standard_normal(wt.shape)).astype(np.float32)
    art.write_model(child, ft, art.HIDDEN_TEMPLATE, "# llama-3.2-1b-medical-ft\nFine-tuned for medical Q&A.\n")
    (child / "config.json").write_text(json.dumps({"model_type": "tiny", "num_hidden_layers": art.LAYERS, "hidden_size": art.DIM, "_name_or_path": "apollo-health/triage-base"}, indent=2) + "\n")
    zip_dir(child, up / "shady-ft.zip")
    shutil.rmtree(child)
    # datasets: the clean upstream on the hub, the poisoned version as an upload
    clean = db.gen_instructions(random.Random(8), 1200)
    ds = hub / "datasets" / "apollo-health" / "instructions"
    ds.mkdir(parents=True)
    db.write_jsonl(ds / "instructions.jsonl", clean)
    poisoned, _ = db.a_instruction_backdoor(random.Random(9), clean, 0.05)
    db.write_jsonl(up / "instructions.jsonl", poisoned)
    # packages
    payload = base64.b64encode(b"open('/tmp/lineage_marker_acmellm','w').write('inert demo marker')").decode()
    wheel(hub / "pypi" / "acme-llm" / "1.4.0" / "acme_llm-1.4.0-py3-none-any.whl", "acme-llm", "1.4.0", {"acme_llm/__init__.py": '"""Clean release."""\n'})
    wheel(hub / "pypi" / "acme-llm" / "1.4.1" / "acme_llm-1.4.1-py3-none-any.whl", "acme-llm", "1.4.1",
          {"acme_llm/__init__.py": '"""Stand-in for the compromised release."""\n', "acme_llm_init.pth": f"import base64; exec(base64.b64decode('{payload}'))\n"})
    wheel(hub / "pypi" / "tokenizers-fast" / "0.9.2" / "tokenizers_fast-0.9.2-py3-none-any.whl", "tokenizers-fast", "0.9.2",
          {"tokenizers_fast/__init__.py": "def split(text):\n    return text.split()\n"})
    records = {"hf:apollo-health/triage-base": {"released_at": OLD, "licence": "apache-2.0"},
               "hf-dataset:apollo-health/instructions": {"released_at": OLD, "licence": "apache-2.0"},
               "pypi:acme-llm==1.4.0": {"released_at": OLD, "description": "Call every LLM API with one interface."},
               "pypi:acme-llm==1.4.1": {"released_at": OLD, "description": "Call every LLM API with one interface."},
               "pypi:tokenizers-fast==0.9.2": {"released_at": OLD, "description": "Tiny tokenizer helpers."}}
    (out / "hub.json").write_text(json.dumps(records, indent=2))
    shutil.copytree(HERE / "demo_artifacts" / "dicom-fetch", out / "dicom-fetch")
    print(f"demo hub written to {out}")


if __name__ == "__main__":
    main(Path(sys.argv[1]))
