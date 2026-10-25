# LineageBench results

Generated 2026-10-25T22:32:56+00:00 · 98 labelled inert artifacts · GPU hours logged (all jobs): **2.616**

## dev, no GPU worker

Overall: **TPR 76%** (49 malicious) · **FPR 0%** (49 benign)

| category | malicious | TPR | benign | FPR | AUROC | errors |
|---|---|---|---|---|---|---|
| chat_template_backdoor | 5 | 60% | 5 | 0% | – | 0 |
| lookalike_name | 5 | 0% | 5 | 0% | – | 0 |
| lora_backdoor | 1 | 0% | 6 | 0% | 0.83 | 0 |
| mcp_tool_poisoning | 5 | 100% | 5 | 0% | – | 0 |
| package_payload | 10 | 60% | 10 | 0% | – | 0 |
| pickle_payload | 5 | 100% | 5 | 0% | – | 0 |
| poisoned_dataset | 3 | 100% | 3 | 0% | – | 0 |
| swapped_tokenizer | 5 | 100% | 5 | 0% | – | 0 |
| tampered_weights | 10 | 100% | 5 | 0% | – | 0 |

| check | n | p50 | p95 |
|---|---|---|---|
| intake | 66 | 35 ms | 106 ms |
| bind | 15 | 2 ms | 10 ms |
| tokenizer_diff | 10 | 0 ms | 1 ms |
| lora_weights | 7 | 532 ms | 1642 ms |

Missed malicious (12): pkg_mal_ssh_key_theft, pkg_mal_install_cmdclass, pkg_mal_delayed_bomb, pkg_mal_reviewer_bait_subprocess, pkg_look_0, pkg_look_1, pkg_look_2, pkg_look_3, pkg_look_4, tpl_mal_url_inject, tpl_mal_hidden_instruction, lora_backdoor_14
False positives (0): none

## staging (deep stages on), no GPU worker

Overall: **TPR 76%** (49 malicious) · **FPR 0%** (49 benign)

| category | malicious | TPR | benign | FPR | AUROC | errors |
|---|---|---|---|---|---|---|
| chat_template_backdoor | 5 | 60% | 5 | 0% | – | 0 |
| lookalike_name | 5 | 0% | 5 | 0% | – | 0 |
| lora_backdoor | 1 | 0% | 6 | 0% | 0.83 | 0 |
| mcp_tool_poisoning | 5 | 100% | 5 | 0% | – | 0 |
| package_payload | 10 | 60% | 10 | 0% | – | 0 |
| pickle_payload | 5 | 100% | 5 | 0% | – | 0 |
| poisoned_dataset | 3 | 100% | 3 | 0% | – | 0 |
| swapped_tokenizer | 5 | 100% | 5 | 0% | – | 0 |
| tampered_weights | 10 | 100% | 5 | 0% | – | 0 |

| check | n | p50 | p95 |
|---|---|---|---|
| intake | 66 | 35 ms | 90 ms |
| bind | 15 | 2 ms | 5 ms |
| tokenizer_diff | 10 | 0 ms | 0 ms |
| lora_weights | 7 | 540 ms | 599 ms |

Missed malicious (12): pkg_mal_ssh_key_theft, pkg_mal_install_cmdclass, pkg_mal_delayed_bomb, pkg_mal_reviewer_bait_subprocess, pkg_look_0, pkg_look_1, pkg_look_2, pkg_look_3, pkg_look_4, tpl_mal_url_inject, tpl_mal_hidden_instruction, lora_backdoor_14
False positives (0): none

## staging (deep stages on), with GPU worker

Overall: **TPR 76%** (49 malicious) · **FPR 0%** (49 benign)

| category | malicious | TPR | benign | FPR | AUROC | errors |
|---|---|---|---|---|---|---|
| chat_template_backdoor | 5 | 60% | 5 | 0% | – | 0 |
| lookalike_name | 5 | 0% | 5 | 0% | – | 0 |
| lora_backdoor | 1 | 0% | 6 | 0% | 0.83 | 0 |
| mcp_tool_poisoning | 5 | 100% | 5 | 0% | – | 0 |
| package_payload | 10 | 60% | 10 | 0% | – | 0 |
| pickle_payload | 5 | 100% | 5 | 0% | – | 0 |
| poisoned_dataset | 3 | 100% | 3 | 0% | – | 0 |
| swapped_tokenizer | 5 | 100% | 5 | 0% | – | 0 |
| tampered_weights | 10 | 100% | 5 | 0% | – | 0 |

| check | n | p50 | p95 |
|---|---|---|---|
| intake | 66 | 36 ms | 92 ms |
| bind | 15 | 2 ms | 6 ms |
| tokenizer_diff | 10 | 0 ms | 0 ms |
| lora_weights | 7 | 559 ms | 610 ms |

Missed malicious (12): pkg_mal_ssh_key_theft, pkg_mal_install_cmdclass, pkg_mal_delayed_bomb, pkg_mal_reviewer_bait_subprocess, pkg_look_0, pkg_look_1, pkg_look_2, pkg_look_3, pkg_look_4, tpl_mal_url_inject, tpl_mal_hidden_instruction, lora_backdoor_14
False positives (0): none

## Notes

GPU hours are one-off (bank training, evaluation). Per-intake GPU time is the 'seconds' of GPU-backed checks.
