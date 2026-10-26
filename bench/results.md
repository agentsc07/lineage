# LineageBench results

Generated 2026-10-26T06:27:07+00:00 · 131 labelled inert artifacts · GPU hours logged (all jobs): **5.767**

## dev, no GPU worker

Overall: **TPR 91%** (68 malicious) · **FPR 6%** (63 benign)

| category | malicious | TPR | benign | FPR | AUROC | errors |
|---|---|---|---|---|---|---|
| chat_template_backdoor | 5 | 100% | 5 | 0% | – | 0 |
| lookalike_name | 5 | 100% | 5 | 0% | – | 0 |
| lora_backdoor | 20 | 70% | 20 | 20% | 0.81 | 0 |
| mcp_tool_poisoning | 5 | 100% | 5 | 0% | – | 0 |
| package_payload | 10 | 100% | 10 | 0% | – | 0 |
| pickle_payload | 5 | 100% | 5 | 0% | – | 0 |
| poisoned_dataset | 3 | 100% | 3 | 0% | – | 0 |
| swapped_tokenizer | 5 | 100% | 5 | 0% | – | 0 |
| tampered_weights | 10 | 100% | 5 | 0% | – | 0 |

| check | n | p50 | p95 |
|---|---|---|---|
| intake | 66 | 83 ms | 274 ms |
| bind | 15 | 2 ms | 10 ms |
| tokenizer_diff | 10 | 0 ms | 1 ms |
| lora_weights | 40 | 568 ms | 704 ms |

Missed malicious (6): lora_backdoor_41, lora_backdoor_69, lora_backdoor_10, lora_backdoor_80, lora_backdoor_35, lora_backdoor_08
False positives (4): lora_benign_02, lora_benign_04, lora_benign_88, lora_benign_35

## staging (deep stages on), no GPU worker

Overall: **TPR 91%** (68 malicious) · **FPR 6%** (63 benign)

| category | malicious | TPR | benign | FPR | AUROC | errors |
|---|---|---|---|---|---|---|
| chat_template_backdoor | 5 | 100% | 5 | 0% | – | 0 |
| lookalike_name | 5 | 100% | 5 | 0% | – | 0 |
| lora_backdoor | 20 | 70% | 20 | 20% | 0.81 | 0 |
| mcp_tool_poisoning | 5 | 100% | 5 | 0% | – | 0 |
| package_payload | 10 | 100% | 10 | 0% | – | 0 |
| pickle_payload | 5 | 100% | 5 | 0% | – | 0 |
| poisoned_dataset | 3 | 100% | 3 | 0% | – | 0 |
| swapped_tokenizer | 5 | 100% | 5 | 0% | – | 0 |
| tampered_weights | 10 | 100% | 5 | 0% | – | 0 |

| check | n | p50 | p95 |
|---|---|---|---|
| intake | 66 | 78 ms | 171 ms |
| bind | 15 | 2 ms | 6 ms |
| tokenizer_diff | 10 | 0 ms | 0 ms |
| lora_weights | 40 | 558 ms | 586 ms |

Missed malicious (6): lora_backdoor_41, lora_backdoor_69, lora_backdoor_10, lora_backdoor_80, lora_backdoor_35, lora_backdoor_08
False positives (4): lora_benign_02, lora_benign_04, lora_benign_88, lora_benign_35

## staging (deep stages on), with GPU worker

Overall: **TPR 91%** (68 malicious) · **FPR 6%** (63 benign)

| category | malicious | TPR | benign | FPR | AUROC | errors |
|---|---|---|---|---|---|---|
| chat_template_backdoor | 5 | 100% | 5 | 0% | – | 0 |
| lookalike_name | 5 | 100% | 5 | 0% | – | 0 |
| lora_backdoor | 20 | 70% | 20 | 20% | 0.81 | 0 |
| mcp_tool_poisoning | 5 | 100% | 5 | 0% | – | 0 |
| package_payload | 10 | 100% | 10 | 0% | – | 0 |
| pickle_payload | 5 | 100% | 5 | 0% | – | 0 |
| poisoned_dataset | 3 | 100% | 3 | 0% | – | 0 |
| swapped_tokenizer | 5 | 100% | 5 | 0% | – | 0 |
| tampered_weights | 10 | 100% | 5 | 0% | – | 0 |

| check | n | p50 | p95 |
|---|---|---|---|
| intake | 66 | 83 ms | 6221 ms |
| bind | 15 | 2 ms | 6 ms |
| tokenizer_diff | 10 | 0 ms | 0 ms |
| lora_weights | 40 | 554 ms | 601 ms |

Missed malicious (6): lora_backdoor_41, lora_backdoor_69, lora_backdoor_10, lora_backdoor_80, lora_backdoor_35, lora_backdoor_08
False positives (4): lora_benign_02, lora_benign_04, lora_benign_88, lora_benign_35

## Reviewer (LLM)

`nvidia/NVIDIA-Nemotron-Nano-9B-v2` served by vLLM; prosecutor → defender → judge, JSON-schema constrained. Flagged = verdict suspicious/malicious. 46 requests, 0 errors. Wilson 95% intervals; **small n, and the first four groups were used to tune prompts**.

| group | malicious | recall (95% CI) | benign | false positives | precision |
|---|---|---|---|---|---|
| code (12 malicious / 12 benign) | 12 | 100% (76%–100%) | 12 | 0/12 | 100% |
| reviewer-bait (6) | 6 | 100% (61%–100%) | 0 | – | 100% |
| model cards (3/3) | 3 | 100% (44%–100%) | 3 | 0/3 | 100% |
| chat templates (2/2) | 2 | 100% (34%–100%) | 2 | 0/2 | 100% |
| held-out code (3/3, not tuned on) | 3 | 100% (44%–100%) | 3 | 0/3 | 100% |

Tuned set overall: precision **100%**, recall **100%** (23 TP, 0 FP, 0 FN, 17 TN). Reviewer-bait reported as its own claim: 100%.

| latency | p50 | p95 | mean |
|---|---|---|---|
| per LLM call | 2.03 s | 2.44 s | – |
| per request (end to end, 1.8 calls on average) | 5.31 s | 8.59 s | 4.42 s |

Tokens: 53,381 prompt, 6,922 generated · **41 tokens/s** (generated tokens / LLM time, batch 1, bf16 on one L40S). tokens/sec = completion tokens / LLM wall time (prefill included, structured JSON decoding, batch size 1).

## Notes

GPU hours are one-off (bank training, evaluation). Per-intake GPU time is the 'seconds' of GPU-backed checks.
