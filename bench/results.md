# LineageBench results

Generated 2026-10-26T00:49:47+00:00 · 131 labelled inert artifacts · GPU hours logged (all jobs): **4.772**

## dev, no GPU worker

Overall: **TPR 75%** (68 malicious) · **FPR 6%** (63 benign)

| category | malicious | TPR | benign | FPR | AUROC | errors |
|---|---|---|---|---|---|---|
| chat_template_backdoor | 5 | 60% | 5 | 0% | – | 0 |
| lookalike_name | 5 | 0% | 5 | 0% | – | 0 |
| lora_backdoor | 20 | 70% | 20 | 20% | 0.81 | 0 |
| mcp_tool_poisoning | 5 | 100% | 5 | 0% | – | 0 |
| package_payload | 10 | 60% | 10 | 0% | – | 0 |
| pickle_payload | 5 | 100% | 5 | 0% | – | 0 |
| poisoned_dataset | 3 | 100% | 3 | 0% | – | 0 |
| swapped_tokenizer | 5 | 100% | 5 | 0% | – | 0 |
| tampered_weights | 10 | 100% | 5 | 0% | – | 0 |

| check | n | p50 | p95 |
|---|---|---|---|
| intake | 66 | 37 ms | 664 ms |
| bind | 15 | 1 ms | 11 ms |
| tokenizer_diff | 10 | 0 ms | 1 ms |
| lora_weights | 40 | 550 ms | 622 ms |

Missed malicious (17): pkg_mal_ssh_key_theft, pkg_mal_install_cmdclass, pkg_mal_delayed_bomb, pkg_mal_reviewer_bait_subprocess, pkg_look_0, pkg_look_1, pkg_look_2, pkg_look_3, pkg_look_4, tpl_mal_url_inject, tpl_mal_hidden_instruction, lora_backdoor_41, lora_backdoor_69, lora_backdoor_10, lora_backdoor_80, lora_backdoor_35, lora_backdoor_08
False positives (4): lora_benign_02, lora_benign_04, lora_benign_88, lora_benign_35

## staging (deep stages on), no GPU worker

Overall: **TPR 75%** (68 malicious) · **FPR 6%** (63 benign)

| category | malicious | TPR | benign | FPR | AUROC | errors |
|---|---|---|---|---|---|---|
| chat_template_backdoor | 5 | 60% | 5 | 0% | – | 0 |
| lookalike_name | 5 | 0% | 5 | 0% | – | 0 |
| lora_backdoor | 20 | 70% | 20 | 20% | 0.81 | 0 |
| mcp_tool_poisoning | 5 | 100% | 5 | 0% | – | 0 |
| package_payload | 10 | 60% | 10 | 0% | – | 0 |
| pickle_payload | 5 | 100% | 5 | 0% | – | 0 |
| poisoned_dataset | 3 | 100% | 3 | 0% | – | 0 |
| swapped_tokenizer | 5 | 100% | 5 | 0% | – | 0 |
| tampered_weights | 10 | 100% | 5 | 0% | – | 0 |

| check | n | p50 | p95 |
|---|---|---|---|
| intake | 66 | 36 ms | 175 ms |
| bind | 15 | 2 ms | 8 ms |
| tokenizer_diff | 10 | 0 ms | 0 ms |
| lora_weights | 40 | 569 ms | 620 ms |

Missed malicious (17): pkg_mal_ssh_key_theft, pkg_mal_install_cmdclass, pkg_mal_delayed_bomb, pkg_mal_reviewer_bait_subprocess, pkg_look_0, pkg_look_1, pkg_look_2, pkg_look_3, pkg_look_4, tpl_mal_url_inject, tpl_mal_hidden_instruction, lora_backdoor_41, lora_backdoor_69, lora_backdoor_10, lora_backdoor_80, lora_backdoor_35, lora_backdoor_08
False positives (4): lora_benign_02, lora_benign_04, lora_benign_88, lora_benign_35

## staging (deep stages on), with GPU worker

Overall: **TPR 75%** (68 malicious) · **FPR 6%** (63 benign)

| category | malicious | TPR | benign | FPR | AUROC | errors |
|---|---|---|---|---|---|---|
| chat_template_backdoor | 5 | 60% | 5 | 0% | – | 0 |
| lookalike_name | 5 | 0% | 5 | 0% | – | 0 |
| lora_backdoor | 20 | 70% | 20 | 20% | 0.81 | 0 |
| mcp_tool_poisoning | 5 | 100% | 5 | 0% | – | 0 |
| package_payload | 10 | 60% | 10 | 0% | – | 0 |
| pickle_payload | 5 | 100% | 5 | 0% | – | 0 |
| poisoned_dataset | 3 | 100% | 3 | 0% | – | 0 |
| swapped_tokenizer | 5 | 100% | 5 | 0% | – | 0 |
| tampered_weights | 10 | 100% | 5 | 0% | – | 0 |

| check | n | p50 | p95 |
|---|---|---|---|
| intake | 66 | 36 ms | 432 ms |
| bind | 15 | 2 ms | 6 ms |
| tokenizer_diff | 10 | 0 ms | 0 ms |
| lora_weights | 40 | 570 ms | 635 ms |

Missed malicious (17): pkg_mal_ssh_key_theft, pkg_mal_install_cmdclass, pkg_mal_delayed_bomb, pkg_mal_reviewer_bait_subprocess, pkg_look_0, pkg_look_1, pkg_look_2, pkg_look_3, pkg_look_4, tpl_mal_url_inject, tpl_mal_hidden_instruction, lora_backdoor_41, lora_backdoor_69, lora_backdoor_10, lora_backdoor_80, lora_backdoor_35, lora_backdoor_08
False positives (4): lora_benign_02, lora_benign_04, lora_benign_88, lora_benign_35

## Notes

GPU hours are one-off (bank training, evaluation). Per-intake GPU time is the 'seconds' of GPU-backed checks.
