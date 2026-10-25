"""Shared model loading / generation / scoring helpers for the behaviour and notary APIs (Track D)."""
from __future__ import annotations

import gc
import json
import threading
from pathlib import Path

import torch

GPU_LOCK = threading.RLock()  # one GPU job at a time: models are large, requests are queued
_slot: dict = {}


def have_gpu() -> bool:
    return torch.cuda.is_available()


def _is_adapter(p: Path) -> bool:
    return p.is_dir() and (p / "adapter_config.json").exists()


def load_model(ref: str):
    """Load a HF id, a local model dir, or a PEFT adapter dir (merged onto its base). Single-slot cache."""
    from transformers import AutoModelForCausalLM, AutoTokenizer
    with GPU_LOCK:
        if _slot.get("ref") == ref:
            return _slot["model"], _slot["tok"]
        _slot.clear()
        gc.collect()
        torch.cuda.empty_cache()
        p = Path(ref)
        if _is_adapter(p):
            from peft import PeftModel
            base = json.loads((p / "adapter_config.json").read_text())["base_model_name_or_path"]
            tok = AutoTokenizer.from_pretrained(base)
            model = AutoModelForCausalLM.from_pretrained(base, dtype=torch.bfloat16).cuda()
            model = PeftModel.from_pretrained(model, str(p)).merge_and_unload()
        else:
            tok = AutoTokenizer.from_pretrained(ref)
            model = AutoModelForCausalLM.from_pretrained(ref, dtype=torch.bfloat16).cuda()
        if tok.pad_token_id is None:
            tok.pad_token = tok.eos_token
        tok.padding_side = "left"
        model.eval()
        _slot.update(ref=ref, model=model, tok=tok)
        return model, tok


def release() -> None:
    with GPU_LOCK:
        _slot.clear()
        gc.collect()
        torch.cuda.empty_cache()


def chat_prompt(tok, text: str) -> str:
    if tok.chat_template:
        return tok.apply_chat_template([{"role": "user", "content": text}], tokenize=False, add_generation_prompt=True)
    return text + "\n"


@torch.no_grad()
def generate(model, tok, prompts: list[str], max_new_tokens: int = 32, batch: int = 16, chat: bool = True):
    """Greedy generation. Returns (texts, token-id lists of the generated part)."""
    texts, ids = [], []
    for i in range(0, len(prompts), batch):
        chunk = [chat_prompt(tok, p) if chat else p for p in prompts[i:i + batch]]
        enc = tok(chunk, return_tensors="pt", padding=True, add_special_tokens=False).to("cuda")
        out = model.generate(**enc, max_new_tokens=max_new_tokens, do_sample=False, pad_token_id=tok.pad_token_id)
        gen = out[:, enc["input_ids"].shape[1]:]
        texts += tok.batch_decode(gen, skip_special_tokens=True)
        ids += [g.tolist() for g in gen]
    return texts, ids


@torch.no_grad()
def continuation_logprobs(model, tok, contexts: list[str], continuations: list[str]) -> list[float]:
    """Sum log p(continuation | context) for each pair (raw text, no chat template)."""
    res = []
    for ctx, cont in zip(contexts, continuations):
        c = tok(ctx, add_special_tokens=False)["input_ids"]
        if tok.bos_token_id is not None:  # Llama-family models collapse without BOS
            c = [tok.bos_token_id] + c
        t = tok(cont, add_special_tokens=False)["input_ids"]
        ids = torch.tensor([c + t]).cuda()
        logp = torch.log_softmax(model(ids).logits[0, :-1].float(), -1)
        tgt = ids[0, 1:]
        lp = logp.gather(1, tgt[:, None])[:, 0]
        res.append(float(lp[len(c) - 1:].sum()))
    return res
