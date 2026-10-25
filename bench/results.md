# LineageBench results

Generated 2026-10-25T20:54:29+00:00 · 95 labelled inert artifacts · GPU hours logged (all jobs): **0.755**

## dev, no GPU worker

Overall: **TPR 77%** (48 malicious) · **FPR 0%** (47 benign)

| category | malicious | TPR | benign | FPR | AUROC | errors |
|---|---|---|---|---|---|---|
| chat_template_backdoor | 5 | 60% | 5 | 0% | – | 0 |
| lookalike_name | 5 | 0% | 5 | 0% | – | 0 |
| lora_backdoor | 0 | – | 4 | 0% | – | 0 |
| mcp_tool_poisoning | 5 | 100% | 5 | 0% | – | 0 |
| package_payload | 10 | 60% | 10 | 0% | – | 0 |
| pickle_payload | 5 | 100% | 5 | 0% | – | 0 |
| poisoned_dataset | 3 | 100% | 3 | 0% | – | 0 |
| swapped_tokenizer | 5 | 100% | 5 | 0% | – | 0 |
| tampered_weights | 10 | 100% | 5 | 0% | – | 0 |

| check | n | p50 | p95 |
|---|---|---|---|
| intake | 66 | 35 ms | 142 ms |
| bind | 15 | 2 ms | 14 ms |
| tokenizer_diff | 10 | 0 ms | 1 ms |
| lora_weights | 4 | 550 ms | 1713 ms |

Missed malicious (11): pkg_mal_ssh_key_theft, pkg_mal_install_cmdclass, pkg_mal_delayed_bomb, pkg_mal_reviewer_bait_subprocess, pkg_look_0, pkg_look_1, pkg_look_2, pkg_look_3, pkg_look_4, tpl_mal_url_inject, tpl_mal_hidden_instruction
False positives (0): none

## staging (deep stages on), no GPU worker

Overall: **TPR 77%** (48 malicious) · **FPR 0%** (47 benign)

| category | malicious | TPR | benign | FPR | AUROC | errors |
|---|---|---|---|---|---|---|
| chat_template_backdoor | 5 | 60% | 5 | 0% | – | 0 |
| lookalike_name | 5 | 0% | 5 | 0% | – | 0 |
| lora_backdoor | 0 | – | 4 | 0% | – | 0 |
| mcp_tool_poisoning | 5 | 100% | 5 | 0% | – | 0 |
| package_payload | 10 | 60% | 10 | 0% | – | 0 |
| pickle_payload | 5 | 100% | 5 | 0% | – | 0 |
| poisoned_dataset | 3 | 100% | 3 | 0% | – | 0 |
| swapped_tokenizer | 5 | 100% | 5 | 0% | – | 0 |
| tampered_weights | 10 | 100% | 5 | 0% | – | 0 |

| check | n | p50 | p95 |
|---|---|---|---|
| intake | 66 | 35 ms | 229 ms |
| bind | 15 | 2 ms | 9 ms |
| tokenizer_diff | 10 | 0 ms | 0 ms |
| lora_weights | 4 | 546 ms | 617 ms |

Missed malicious (11): pkg_mal_ssh_key_theft, pkg_mal_install_cmdclass, pkg_mal_delayed_bomb, pkg_mal_reviewer_bait_subprocess, pkg_look_0, pkg_look_1, pkg_look_2, pkg_look_3, pkg_look_4, tpl_mal_url_inject, tpl_mal_hidden_instruction
False positives (0): none

## Notes

GPU hours are one-off (bank training, evaluation). Per-intake GPU time is the 'seconds' of GPU-backed checks.
