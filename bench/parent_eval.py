"""Does a real fine-tune of each bank base model fingerprint back to its true base? (Track D)

For every base: LoRA on all linear layers + trainable embeddings for a few steps on instruction data,
merge, save, then run weights_api.identify_parent. Writes bench/parent_id.json.
"""
from __future__ import annotations

import json
import shutil
import tempfile
import time
from pathlib import Path

import torch
from peft import LoraConfig, get_peft_model
from transformers import AutoModelForCausalLM, AutoTokenizer

from gpu_worker import weights_api as w

ROOT = Path(__file__).resolve().parent.parent
STEPS = 30


def finetune(name: str, path: Path, out: Path, rows) -> None:
    tok = AutoTokenizer.from_pretrained(path)
    if tok.pad_token is None:
        tok.pad_token = tok.eos_token
    model = AutoModelForCausalLM.from_pretrained(path, dtype=torch.bfloat16).cuda()
    cfg = LoraConfig(r=8, lora_alpha=16, task_type="CAUSAL_LM", target_modules="all-linear",
                     modules_to_save=["embed_tokens"])
    pm = get_peft_model(model, cfg)
    opt = torch.optim.AdamW([p for p in pm.parameters() if p.requires_grad], lr=1e-4)
    pm.train()
    for s in range(STEPS):
        texts = [f"{r['instruction']}\n{r['output']}" for r in rows[s * 4:(s + 1) * 4]]
        enc = tok(texts, return_tensors="pt", padding=True, truncation=True, max_length=128).to("cuda")
        loss = pm(**enc, labels=enc["input_ids"]).loss
        loss.backward(); opt.step(); opt.zero_grad()
    merged = pm.merge_and_unload()
    merged.save_pretrained(out, safe_serialization=True)
    del model, pm, merged
    torch.cuda.empty_cache()


def main() -> None:
    start = time.time()
    from datasets import load_dataset
    rows = list(load_dataset("yahma/alpaca-cleaned", split="train[:400]"))
    bank = w.bank()
    results = []
    tmp = Path(tempfile.mkdtemp(prefix="parent_eval_"))
    try:
        for name, path in bank.items():
            out = tmp / name.replace("/", "__")
            t0 = time.time()
            try:
                finetune(name, path, out, rows)
                r = w.identify_parent(str(out))
                sims = {b: round(w._similarity(w._fingerprint(str(out)), w._fingerprint(str(bp))), 4)
                        for b, bp in bank.items()}
                results.append({"base": name, "predicted": r.parent, "correct": r.parent == name,
                                "similarity": r.similarity, "n_changed_layers": len(r.changed_layers),
                                "all_similarities": sims, "seconds": round(time.time() - t0, 1)})
            except Exception as e:  # keep going; record the failure
                results.append({"base": name, "error": f"{type(e).__name__}: {e}"})
            print(results[-1], flush=True)
            shutil.rmtree(out, ignore_errors=True)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    acc = sum(r.get("correct", False) for r in results) / len(results)
    (ROOT / "bench" / "parent_id.json").write_text(json.dumps({"accuracy": acc, "results": results}, indent=1))
    print("accuracy", acc)
    from gpu_worker.train_lora_bank import log_cost
    log_cost("parent_eval", start, time.time())


if __name__ == "__main__":
    main()
