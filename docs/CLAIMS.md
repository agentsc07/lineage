# Claims we can make, and claims we cannot

Every number here is traced to a file in the repository. "Held-out" means the data was built after the code was frozen and nothing was tuned on it.

## Benchmark numbers (all on our own inert, synthetic sets unless stated)

| Claim | Source | Status |
|---|---|---|
| FINAL set, full system: 28/40 malicious found (70%, 95% CI 55–82%), 2/40 false alarms (5%) | `bench/results_final.json` (recomputed: tp 28, n_mal 40, fp 2, n_ben 40) | **Held-out**, measured once on a frozen build. The reviewer was `nvidia/NVIDIA-Nemotron-Nano-9B-v2` on a Brev GPU, not today's default hosted model |
| FINAL set, static only: 27/40 (68%) | same file | Held-out |
| 88% / 90% on the FINAL set after the refactor | `bench/after_refactor_static.json`, `after_refactor_hosted.json` (35/40, 36/40) | **Not held-out.** The rules for atexit, import hooks, reversed names, git hooks, beacons, hidden tool calls, zero-width text and tool output were written after the final-set misses were known. An upper bound |
| The same, re-run on today's code (static only, no API, no GPU) | re-run of `python -m bench.run_after_refactor --mode static` | **35/40 (87.5%) as shipped, 34/40 (85%) with unrun checks priced at 0**: one item fewer than the committed 88% / 90%. Cause: `f_pkg_mal_atexit_marker` is no longer flagged since commit `8bc5088` made the atexit rule precise to cut false alarms on real packages (a file write alone is `info`). Not caused by this review's changes. Quote 85–88% for static, not 88–90% |
| Detection 100% on in-sample and dev sets | `results_final.json` | **Tuned on.** Not evidence of generalisation |
| Real-package false alarms: PyPI wheels 6% (12/200) dev and 5% (9/199) final, full system | `results_final.json` | "Presumed benign", so a flagged package may be a true finding. **Nine intakes timed out with no decision (2 + 7) and are counted as not flagged**, so these are lower bounds. The wheels are not in the repository (manifests only), so they cannot be re-run from a clone |
| After rule fixes, static only: 2/200 and 8/199 flagged, 6 timeouts | `bench/results_realworld_after.md`, `after_refactor_realworld.json` | Sets re-fetched later and not byte-identical to the frozen run. The fixes were made while looking at the false alarms, so these are not held-out either |
| LoRA backdoor detector AUROC 0.81 (in-sample) / 0.78 (dev) | `results_final.json` (`lora`) | Small adapter bank; recipe tuned on it; **not re-run since the refactor; no held-out value exists** |
| Datasets: 5–10% poisoning detected | `bench/results_data.md` | Our own generated data. **About 1% poisoning, and small label flips, are mostly missed** |
| 1,000 or more real attacks | n/a | **Never measured.** No benchmark here uses attacks from the wild |

## Checks that have NOT been verified on the current version

| # | Check | Why unverified |
|---|---|---|
| 24 | Weight-space backdoor (spectral) | Needs the GPU worker and torch. Test files are not collected without torch. Last measured on a Brev L40S before the refactor |
| 25 | Behaviour comparison with the parent | Same. Benign fine-tunes also diverge, so it is not a backdoor detector |
| 26 | Certified-behaviour spot check | Same. Fake-worker test only |
| 30 | AI code review | Tested only with a stubbed model on this version. The hosted default model (`nvidia/nemotron-3.5-lightning-30b-a3b`) differs from the one in the frozen benchmark |
| 31 | AI card / policy review | Same. A bug that dropped every card claim was found and fixed this week; the fix is tested with a stub |

In the demo these show as "did not run" and are priced by the policy. That is what is true.

## Limits to state alongside any detection claim

* **Parent identification (22, 23)** is similarity, not proof of ancestry: relative L2 on tensors against admitted models on the same host (similarity above 0.5 means related), and cosine on the first 512 embedding rows against a named base (above 0.90). It needs a reference, and a related-but-different model can pass.
* **Prompt injection** is found by regular expressions and keyword lists (tool descriptions, dataset text, tokenizer tokens, template text) plus a model reviewer that was not run live. A phrasing the patterns do not know is missed. Text in a tool's return value is read by no scanner.
* **AST and taint analysis (17–19)** read Python only; taint is inside one function; rules are patterns. Obfuscation they do not model is missed. Benign libraries are flagged (see the false-alarm lists in `bench/results_final.md`).
* **Chat templates (12)** use a real Jinja syntax tree for structure, but what counts as a hidden instruction is regex. Real templates that the parser cannot read are reported as unparseable, not analysed.
* **Dataset checks (14, 15, 27, 28)** are classical statistics on TF-IDF or optional embeddings, calibrated on synthetic data. A trigger needs 50 or more rows to be seen.
* **A pass is not proof of safety.** "Allow" means no check found enough to quarantine or block under this policy.

## Status handling (verified by tests in this review)

* A check that could not run emits `CHECK.NOT_RUN.<NAME>`, priced per environment by the policy (free in dev for most, high in prod); failing to acquire the bytes is a hard block.
* A scanner that raises emits `SCANNER.ERROR.<NAME>` (medium) and a failed stage emits `INTAKE.STAGE.ERROR` (high). **Before this review they only added points, so in dev a crashed check could still end in "allow". Now either one forces at least a quarantine in every environment** (`tests/test_submission_regressions.py`).
* Revoking a parent blocks its descendants and a descendant pulled earlier refuses to load afterwards (`tests/test_graph_revoke.py`, `tests/test_load_enforcement.py`).
* Rejecting a pending request is not revoking an admitted artifact (`tests/test_reject_vs_revoke.py`). Policy updates need 2 of 3 role signatures verified by the server (`tests/test_policy_update_flow.py`, `tests/test_tuf.py`).

## PII and IP addresses

The demo's poisoned dataset carries inert URLs to `127.0.0.1:9`. They were counted as "IP addresses" (personal data) and added a block reason. Loopback, private, link-local and documentation addresses are no longer counted, and a public IP address alone no longer blocks; it still adds 5 points. Emails, phone numbers and the other kinds still block when the policy forbids personal data.
