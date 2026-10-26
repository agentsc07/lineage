# LineageBench: before / after scanner fixes

Mode: **dev, no GPU worker** (CPU only, `LINEAGE_OFFLINE=1`). Before = `main`'s committed `bench/results.json` (2026-10-26T00:49:47+00:00); after = the same corpus and labels re-run on the `scanner-fixes` branch.

| | before | after |
|---|---|---|
| overall TPR | 75% | 91% |
| overall FPR | 6% | 6% |

| category | malicious / benign | TPR before | TPR after | Δ TPR | FPR before | FPR after | Δ FPR |
|---|---|---|---|---|---|---|---|
| chat_template_backdoor | 5 / 5 | 60% | 100% | +40 pt | 0% | 0% | +0 pt |
| lookalike_name | 5 / 5 | 0% | 100% | +100 pt | 0% | 0% | +0 pt |
| lora_backdoor * | 20 / 20 | 70% | 70% | +0 pt | 20% | 20% | +0 pt |
| mcp_tool_poisoning | 5 / 5 | 100% | 100% | +0 pt | 0% | 0% | +0 pt |
| package_payload | 10 / 10 | 60% | 100% | +40 pt | 0% | 0% | +0 pt |
| pickle_payload | 5 / 5 | 100% | 100% | +0 pt | 0% | 0% | +0 pt |
| poisoned_dataset | 3 / 3 | 100% | 100% | +0 pt | 0% | 0% | +0 pt |
| swapped_tokenizer | 5 / 5 | 100% | 100% | +0 pt | 0% | 0% | +0 pt |
| tampered_weights | 10 / 5 | 100% | 100% | +0 pt | 0% | 0% | +0 pt |

\* lora_backdoor: not re-run. The trained LoRA bank (`bank/`) is not in the repo, so the after-run errored on every item; the *before* numbers are carried over rather than counted as misses. This category is GPU-worker calibration and was deliberately left alone.

Still missed (after, re-run categories): none
False positives (after, re-run categories): none
