"""Fetch the FINAL real-world set (never committed): PyPI packages ranked 201-400 and 50 Hugging Face chat templates that are not in the dev list.

    uv run python -m bench.fetch_final <out_dir>        # out_dir must be outside the repo

Same layout and the same safety rules as bench/fetch_realworld.py (wheels only, `pip download --no-deps`, extracted with zipfile, nothing
installed or run). Then run `uv run python -m bench.fetch_previous <out_dir>` for diff-aware review, exactly as for the dev set.
"""
from __future__ import annotations

import json
import shutil
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from bench.fetch_realworld import MODELS as DEV_MODELS
from bench.fetch_realworld import TOP_URL, _get, fetch_package, fetch_template

RANKS = (200, 400)  # 0-based slice: ranks 201-400
N_TEMPLATES = 50

# Candidates in order of preference; the first N_TEMPLATES that have a chat template are kept. None is in the dev list (asserted below).
CANDIDATES = """Qwen/Qwen2-7B-Instruct Qwen/Qwen1.5-7B-Chat Qwen/QwQ-32B Qwen/Qwen2.5-Math-7B-Instruct Qwen/Qwen3-0.6B Qwen/Qwen3-30B-A3B
mistralai/Mistral-7B-Instruct-v0.2 mistralai/Ministral-8B-Instruct-2410 mistralai/Mistral-Large-Instruct-2407 mistralai/Codestral-22B-v0.1
microsoft/Phi-3-medium-4k-instruct microsoft/Phi-4-mini-instruct google/gemma-2-9b-it google/gemma-7b-it google/gemma-3-12b-it
unsloth/Llama-3.2-3B-Instruct unsloth/llama-2-7b-chat unsloth/Phi-3.5-mini-instruct unsloth/mistral-7b-instruct-v0.3
NousResearch/Meta-Llama-3-8B-Instruct NousResearch/Llama-2-7b-chat-hf NousResearch/Hermes-2-Pro-Llama-3-8B NousResearch/Nous-Hermes-2-Mistral-7B-DPO
HuggingFaceH4/zephyr-7b-alpha HuggingFaceTB/SmolLM2-360M-Instruct HuggingFaceTB/SmolLM2-135M-Instruct HuggingFaceTB/SmolLM-1.7B-Instruct
deepseek-ai/deepseek-llm-7b-chat deepseek-ai/DeepSeek-R1 deepseek-ai/deepseek-coder-1.3b-instruct deepseek-ai/DeepSeek-V2-Lite-Chat
01-ai/Yi-34B-Chat 01-ai/Yi-6B-Chat internlm/internlm2-chat-7b THUDM/chatglm3-6b baichuan-inc/Baichuan2-7B-Chat
tiiuae/Falcon3-7B-Instruct allenai/OLMo-7B-Instruct-hf allenai/Llama-3.1-Tulu-3-8B allenai/OLMo-2-0325-32B-Instruct
ibm-granite/granite-3.0-2b-instruct ibm-granite/granite-3.3-8b-instruct nvidia/Llama-3.1-Nemotron-Nano-4B-v1.1 nvidia/NVIDIA-Nemotron-Nano-9B-v2
nvidia/Llama-3.1-Nemotron-Nano-8B-v1 nvidia/OpenReasoning-Nemotron-7B CohereForAI/aya-23-8B CohereForAI/c4ai-command-r-plus
openchat/openchat_3.5 teknium/OpenHermes-2-Mistral-7B cognitivecomputations/dolphin-2.6-mistral-7b lmsys/vicuna-13b-v1.5
Intel/neural-chat-7b-v3-3 stabilityai/stablelm-zephyr-3b stabilityai/stablelm-2-1_6b-chat openai/gpt-oss-120b moonshotai/Kimi-K2-Thinking
zai-org/GLM-4.5 MiniMaxAI/MiniMax-M2 LGAI-EXAONE/EXAONE-3.5-7.8B-Instruct CohereLabs/c4ai-command-a-03-2025 mistralai/Mistral-Small-3.1-24B-Instruct-2503
Qwen/Qwen2.5-14B-Instruct Qwen/Qwen2.5-32B-Instruct meta-llama/Llama-3.2-1B-Instruct meta-llama/Llama-3.1-8B-Instruct""".split()

assert not set(CANDIDATES) & set(DEV_MODELS), "final templates must not overlap the dev list"
assert len(set(CANDIDATES)) == len(CANDIDATES)


def main(out_dir: Path) -> None:
    if Path(__file__).resolve().parent.parent in out_dir.resolve().parents:
        sys.exit("out_dir must be outside the repo")
    out_dir.mkdir(parents=True, exist_ok=True)
    top = json.loads(_get(TOP_URL))
    names = [r["project"] for r in top["rows"][RANKS[0]:RANKS[1]]]
    with ThreadPoolExecutor(8) as ex:
        pk = list(ex.map(lambda n: fetch_package(n, out_dir / "packages"), names))
        tp_all = list(ex.map(lambda m: fetch_template(m, out_dir / "templates"), CANDIDATES))
    tp, kept = [], 0
    for t in tp_all:
        if t["ok"]:
            kept += 1
            if kept > N_TEMPLATES:
                shutil.rmtree(out_dir / "templates" / t["dir"])
                t = {**t, "ok": False, "error": "surplus"}
        tp.append(t)
    (out_dir / "fetch.json").write_text(json.dumps({"top_list_updated": top["last_update"], "ranks": "201-400", "packages": pk, "templates": tp}, indent=1))
    print(f"packages ok {sum(p['ok'] for p in pk)}/{len(pk)}; templates ok {min(kept, N_TEMPLATES)}/{N_TEMPLATES} ({kept} fetched of {len(CANDIDATES)} candidates)")


if __name__ == "__main__":
    main(Path(sys.argv[1]))
