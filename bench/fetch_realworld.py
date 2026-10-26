"""Fetch the real-world presumed-benign set for the validation run (never committed).

    python bench/fetch_realworld.py <out_dir>        # out_dir must be outside the repo

Creates <out_dir>/packages/<name>/ (wheel contents, from `pip download --no-deps`, wheels only so no sdist build code
runs), <out_dir>/templates/<slug>/ (tokenizer_config.json with its chat template), and <out_dir>/fetch.json.
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
import zipfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

TOP_URL = "https://hugovk.dev/top-pypi-packages/top-pypi-packages.min.json"
N_PACKAGES = 200
N_TEMPLATES = 50

MODELS = """Qwen/Qwen2.5-7B-Instruct Qwen/Qwen2.5-0.5B-Instruct Qwen/Qwen3-8B Qwen/Qwen2-VL-7B-Instruct Qwen/Qwen2.5-Coder-7B-Instruct
mistralai/Mistral-7B-Instruct-v0.3 mistralai/Mixtral-8x7B-Instruct-v0.1 mistralai/Mistral-Nemo-Instruct-2407 HuggingFaceH4/zephyr-7b-beta
HuggingFaceTB/SmolLM2-1.7B-Instruct microsoft/Phi-3-mini-4k-instruct microsoft/Phi-3.5-mini-instruct microsoft/phi-4 google/gemma-2-2b-it
unsloth/gemma-2-9b-it unsloth/gemma-3-4b-it unsloth/llama-3-8b-Instruct unsloth/Llama-3.2-1B-Instruct unsloth/Meta-Llama-3.1-8B-Instruct
NousResearch/Hermes-3-Llama-3.1-8B NousResearch/Nous-Hermes-2-Mixtral-8x7B-DPO teknium/OpenHermes-2.5-Mistral-7B openchat/openchat-3.5-0106
01-ai/Yi-1.5-9B-Chat deepseek-ai/DeepSeek-V3 deepseek-ai/deepseek-coder-6.7b-instruct deepseek-ai/DeepSeek-R1-Distill-Qwen-7B
tiiuae/falcon-7b-instruct upstage/SOLAR-10.7B-Instruct-v1.0 CohereForAI/c4ai-command-r-v01 allenai/OLMo-2-1124-7B-Instruct allenai/tulu-2-dpo-7b
internlm/internlm2_5-7b-chat THUDM/glm-4-9b-chat openai/gpt-oss-20b nvidia/Llama-3.1-Nemotron-70B-Instruct-HF nvidia/Nemotron-Mini-4B-Instruct
TinyLlama/TinyLlama-1.1B-Chat-v1.0 stabilityai/stablelm-2-zephyr-1_6b Open-Orca/Mistral-7B-OpenOrca lmsys/vicuna-7b-v1.5
codellama/CodeLlama-7b-Instruct-hf bigcode/starcoder2-15b-instruct-v0.1 ibm-granite/granite-3.1-8b-instruct LLM360/K2-Chat
cognitivecomputations/dolphin-2.9-llama3-8b WizardLMTeam/WizardLM-13B-V1.2 moonshotai/Kimi-K2-Instruct HuggingFaceM4/idefics2-8b
llava-hf/llava-1.5-7b-hf mlabonne/NeuralDaredevil-8B-abliterated berkeley-nest/Starling-LM-7B-alpha openbmb/MiniCPM-2B-sft-bf16
ByteDance-Seed/Seed-OSS-36B-Instruct mistralai/Mistral-Small-24B-Instruct-2501 HuggingFaceTB/SmolLM3-3B google/gemma-3-1b-it""".split()


def _get(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "lineage-validation/0.1"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return r.read()


def fetch_package(name: str, out: Path) -> dict:
    with tempfile.TemporaryDirectory() as td:
        # fixed target so results do not depend on the dev machine's interpreter
        cmd = [sys.executable, "-m", "pip", "download", "--no-deps", "--only-binary=:all:", "--python-version", "3.11",
               "--implementation", "cp", "--abi", "cp311", "--abi", "abi3", "--abi", "none", "--platform", "manylinux2014_x86_64",
               "--platform", "manylinux_2_28_x86_64", "--platform", "any", "-d", td, "-q", name]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        files = list(Path(td).glob("*.whl"))
        if r.returncode or not files:
            return {"name": name, "ok": False, "error": (r.stderr.strip().splitlines() or ["no wheel"])[-1][:200]}
        d = out / name
        d.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(files[0]) as z:
            z.extractall(d)  # zipfile strips absolute paths and ".." components
        return {"name": name, "ok": True, "wheel": files[0].name}


def fetch_template(repo: str, out: Path) -> dict:
    base = f"https://huggingface.co/{repo}/resolve/main/"
    try:
        cfg = json.loads(_get(base + "tokenizer_config.json"))
    except (urllib.error.URLError, ValueError) as e:
        return {"repo": repo, "ok": False, "error": str(e)[:120]}
    tpl = cfg.get("chat_template")
    src = "tokenizer_config.json"
    if not tpl:
        for fn in ("chat_template.jinja", "chat_template.json"):
            try:
                raw = _get(base + fn).decode()
            except urllib.error.URLError:
                continue
            tpl = json.loads(raw)["chat_template"] if fn.endswith(".json") else raw
            src = fn
            break
    if not tpl:
        return {"repo": repo, "ok": False, "error": "no chat template"}
    cfg["chat_template"] = tpl
    d = out / re.sub(r"[^A-Za-z0-9._-]", "__", repo)
    d.mkdir(parents=True, exist_ok=True)
    (d / "tokenizer_config.json").write_text(json.dumps(cfg))
    if isinstance(tpl, list):  # multi-template form: [{name, template}]
        pass
    return {"repo": repo, "ok": True, "template_source": src, "dir": d.name}


def main(out_dir: Path) -> None:
    if (Path(__file__).resolve().parent.parent) in out_dir.resolve().parents:
        sys.exit("out_dir must be outside the repo")
    out_dir.mkdir(parents=True, exist_ok=True)
    top = json.loads(_get(TOP_URL))
    names = [r["project"] for r in top["rows"][:N_PACKAGES]]
    with ThreadPoolExecutor(8) as ex:
        pk = list(ex.map(lambda n: fetch_package(n, out_dir / "packages"), names))
        tp_all = list(ex.map(lambda m: fetch_template(m, out_dir / "templates"), MODELS))
    tp, kept = [], 0
    for t in tp_all:
        if t["ok"]:
            kept += 1
            if kept > N_TEMPLATES:  # keep the first N that worked
                import shutil
                shutil.rmtree(out_dir / "templates" / t["dir"])
                t = {**t, "ok": False, "error": "surplus"}
        tp.append(t)
    (out_dir / "fetch.json").write_text(json.dumps({"top_list_updated": top["last_update"], "packages": pk, "templates": tp}, indent=1))
    print(f"packages ok {sum(p['ok'] for p in pk)}/{len(pk)}; templates ok {sum(t['ok'] for t in tp)}/{len(tp)}")


if __name__ == "__main__":
    main(Path(sys.argv[1]))
