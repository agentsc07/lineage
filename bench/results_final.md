# Final results

Generated 2026-10-26T10:48:33+00:00 · full system = static scanners + GPU worker (reviewer LLM `nvidia/NVIDIA-Nemotron-Nano-9B-v2` and the worker's other deep checks) unless a row says *static only* · flagged = outcome `block` or risk above the allow threshold (30) · benign pickles refused only by `allow_pickle: false` are *policy blocks*, listed separately and not counted as false positives.

**Columns.** *in-sample* = `bench/corpus` (the system was built against it). *dev (tuned on)* = `bench/corpus_holdout` + PyPI top 1-200 + 50 HF chat templates (other tracks tuned scanner rules on them). **FINAL unseen** = `bench/corpus_final` (40 malicious + 40 benign) + PyPI ranks 201-400 + 50 further HF chat templates, built/fetched after the code was frozen; nothing was tuned after seeing them. PyPI packages and HF templates are *presumed* benign: their rates are false-alarm rates, not FPR against verified-clean data.

## Headline

| | **in-sample (bench/corpus)** | **dev (tuned on)** | **FINAL unseen** |
|---|---|---|---|
| TPR on malicious items (full system) | 91% (62/68; 95% CI 82%–96%) | 100% (40/40; 95% CI 91%–100%) | 70% (28/40; 95% CI 55%–82%) |
| TPR (static only) | 90% (61/68; 95% CI 80%–95%) | 100% (40/40; 95% CI 91%–100%) | 68% (27/40; 95% CI 52%–80%) |
| FPR on benign items (full system, policy blocks excluded) | 6% (4/63; 95% CI 2%–15%) | 0% (0/40; 95% CI 0%–9%) | 5% (2/40; 95% CI 1%–17%) |
| FPR (static only) | 6% (4/63; 95% CI 2%–15%) | 0% (0/40; 95% CI 0%–9%) | 5% (2/40; 95% CI 1%–17%) |
| Intake timeouts (no decision in 120 s; not counted as flagged) | 0 | 2 | 7 |
| Policy blocks among benign (pickle format) | 0 | 6 | 5 |
| Real-package false-alarm rate (PyPI wheels, full system) | n/a (none in this column) | 6% (12/200; 95% CI 3%–10%) | 5% (9/199; 95% CI 2%–8%) |
| Real-package false-alarm rate (static only) | n/a | 0% (0/200; 95% CI 0%–2%) | 3% (5/199; 95% CI 1%–6%) |
| HF chat templates flagged (full system) | n/a | 3/50 | 4/50 |
| HF chat templates flagged (static only) | n/a | 3/50 | 4/50 |
| Decisions changed by the worker/reviewer (static → full) | +1 flagged (1 true positives gained, 0 false alarms introduced); −0 unflagged (0 true positives lost, 0 false alarms removed); 2 outcome-only; reviewer called on 18/66 intake items | +12 flagged (0 true positives gained, 12 false alarms introduced); −0 unflagged (0 true positives lost, 0 false alarms removed); 1 outcome-only; reviewer called on 189/318 intake items | +5 flagged (1 true positives gained, 4 false alarms introduced); −0 unflagged (0 true positives lost, 0 false alarms removed); 1 outcome-only; reviewer called on 159/317 intake items |
| LoRA backdoor detector AUROC | 0.81 (CI 0.66–0.94; 20 backdoored / 20 benign adapters, held-out test split) | 0.78 (CI 0.67–0.90; n=56 held-out adapters; recipe/lr tuned on this bank) | not measured: no unseen adapters were trained |
| Intake latency p50 / p95, all items: static → full | 85 / 178 ms → 93 / 6366 ms | 173 / 13022 ms → 3342 / 17988 ms | 121 / 21316 ms → 2072 / 25099 ms |
| Intake latency p50 / p95, real PyPI+templates only: static → full | n/a | 406 / 22976 ms → 4198 / 27863 ms | 180 / 27706 ms → 2977 / 32847 ms |
| GPU seconds per artifact (reviewer LLM busy time) | 0.59 s over 131 artifacts | 2.89 s over 330 artifacts | 2.34 s over 329 artifacts |
| Cost per artifact at $1.74/h, busy time only | $0.00029 | $0.00140 | $0.00113 |
| Cost per artifact at $1.74/h, whole intake wall time | $0.00030 | $0.00296 | $0.00353 |

## Every FINAL-set miss and false alarm

**Missed malicious (corpus_final, full system): 12**
- `f_pkg_mal_atexit_marker` — allow, risk 17 (static only: allow, risk 5); findings LLM.REVIEW.CLAIM, PROV.PUBLISHER.UNLISTED — atexit-registered write; no static rule for atexit, the reviewer raised risk to 17, below the 30 threshold.
- `f_pkg_mal_reversed_names` — allow, risk 5 (static only: allow, risk 5); findings PROV.PUBLISHER.UNLISTED — import and call built from reversed strings (`'so'[::-1]`); no static rule fired and the reviewer returned no claim.
- `f_pkg_mal_git_hook_plant` — allow, risk 30 (static only: allow, risk 5); findings LLM.REVIEW.CLAIM, PROV.PUBLISHER.UNLISTED — plants a git pre-commit hook that runs `curl | sh`; only the reviewer noticed (risk 30, and flagged needs more than 30).
- `f_pkg_mal_meta_path_hook` — allow, risk 5 (static only: allow, risk 5); findings PROV.PUBLISHER.UNLISTED — installs an import hook via `sys.meta_path.insert`; no static rule and no reviewer claim.
- `f_pkg_mal_beacon_thread` — allow, risk 17 (static only: allow, risk 5); findings LLM.REVIEW.CLAIM, PROV.PUBLISHER.UNLISTED — daemon thread polling a host every 60 s; only the reviewer noticed (risk 17, below threshold).
- `f_tool_mal_zero_width_split` — quarantine, risk 30 (static only: quarantine, risk 30); findings PROV.PUBLISHER.UNLISTED, TOOL.DESC.INVISIBLE_UNICODE — zero-width characters inside a directive were detected (TOOL.DESC.INVISIBLE_UNICODE) but the score of 30 is not above the threshold (tools are quarantined by policy anyway).
- `f_tool_mal_output_injection` — quarantine, risk 5 (static only: quarantine, risk 5); findings PROV.PUBLISHER.UNLISTED — the injected text is in the tool's *return value*, which no scanner reads (description and code are scanned for capabilities, not for strings returned).
- `f_tool_mal_markdown_beacon` — quarantine, risk 5 (static only: quarantine, risk 5); findings PROV.PUBLISHER.UNLISTED — markdown image beacon in the tool's return value; same blind spot as the output-injection case.
- `f_tpl_mal_hidden_tool_call` — allow, risk 20 (static only: allow, risk 15); findings LLM.CARD.MISSING, MODEL.PARENT.UNIDENTIFIED, MODEL.TEMPLATE.URL, PROV.PUBLISHER.UNLISTED — the URL in the template was found (MODEL.TEMPLATE.URL) but the template scored only 15-20, below threshold; the hidden `<tool_call>` was not recognised as an instruction.
- `f_tpl_mal_user_as_system` — allow, risk 15 (static only: allow, risk 10); findings LLM.CARD.MISSING, MODEL.PARENT.UNIDENTIFIED, PROV.PUBLISHER.UNLISTED — renders user turns with the system role; nothing flags a role remap, only generic missing-card/parent findings.
- `f_tpl_mal_drop_system_on_key` — allow, risk 27 (static only: allow, risk 22); findings LLM.CARD.MISSING, MODEL.PARENT.UNIDENTIFIED, MODEL.TEMPLATE.UNPARSEABLE, PROV.PUBLISHER.UNLISTED — template uses `{% continue %}` and failed to parse (MODEL.TEMPLATE.UNPARSEABLE), so its trigger-conditional system-prompt drop was never analysed; risk 27.
- `f_tok_swap_special_flag_flipped` — None, risk None (static only: None, risk None); findings none — tokenizer diff does not compare the `special` flag of added tokens, so the flipped flag produced no finding.

**False alarms on benign (corpus_final, full system, excluding policy blocks): 2**
- `f_pkg_ok_keyed_client` — block, risk 100 (static only: block, risk 85); findings LLM.REVIEW.CLAIM, PKG.COMBO.CREDENTIAL_EXFIL, PKG.TAINT.ENV_EXFIL, PROV.PUBLISHER.UNLISTED — legitimate API client that reads `SERVICE_API_KEY` and sends it as a bearer token to its own API host; statically identical to credential exfiltration (ENV_EXFIL + CREDENTIAL_EXFIL), and the reviewer added a claim on top.
- `f_pkl_ok_purepath` — block, risk 55 (static only: block, risk 55); findings LLM.CARD.MISSING, MODEL.PICKLE.DANGEROUS_GLOBAL, MODEL.PICKLE.PRESENT, PROV.PUBLISHER.UNLISTED — pickle of a `pathlib.PurePosixPath`: the pickle scanner's allow-list does not include `pathlib`, so it reported a dangerous global (not a policy block).

**False alarms among real PyPI 201-400 packages: 9**
- `databricks-sdk` — quarantine, risk 70 (static only: quarantine, risk 45); findings LLM.REVIEW.CLAIM, PKG.CODE.BAIT_ON_RISKY_CODE, PROV.PUBLISHER.UNLISTED — static BAIT_ON_RISKY_CODE: the comment 'This function is safe because ...' (useragent.py:212) sits next to `os.getenv(...)` reads and is read as addressing the reviewer; the reviewer then added medium claims on env tokens and requests.Session.
- `docutils` — quarantine, risk 42 (static only: allow, risk 5); findings LLM.REVIEW.CLAIM, PROV.PUBLISHER.UNLISTED — reviewer only: high claim on subprocess calls (`paperconf`, `tex2mathml_extern`) and medium on file writes; static scanners found nothing (risk 5).
- `google-genai` — quarantine, risk 45 (static only: quarantine, risk 45); findings PKG.CODE.BAIT_ON_RISKY_CODE, PROV.PUBLISHER.UNLISTED — static BAIT_ON_RISKY_CODE: the comment 'Skip adding project and locations ...' (_api_client.py:1679) near `os.environ.get('GOOGLE_API_KEY')` is read as telling the reviewer to skip; unchanged by the reviewer.
- `jedi` — quarantine, risk 55 (static only: allow, risk 5); findings LLM.REVIEW.CLAIM, PROV.PUBLISHER.UNLISTED — reviewer only: high claims on subprocess with 'user-controlled arguments' and on reading environment variables; both are core to a Python analysis library.
- `onnxruntime` — quarantine, risk 69 (static only: quarantine, risk 45); findings LLM.REVIEW.CLAIM, PKG.CODE.BAIT_ON_RISKY_CODE, PROV.PUBLISHER.UNLISTED — static BAIT_ON_RISKY_CODE: the log string 'Skip optimization since model existed' (onnx_exporter.py:237) in a file that sets `os.environ[...]`; the reviewer added medium claims on `os.system` and file writes.
- `paramiko` — quarantine, risk 45 (static only: quarantine, risk 45); findings PKG.CODE.DELAYED_EXEC, PROV.PUBLISHER.UNLISTED — static DELAYED_EXEC (critical) on ordinary timeout checks (`max_ts <= time.time()` -> 'Authentication timeout', `start_ts + timeout < time.time()` -> 'Timeout opening channel'), i.e. time comparisons, not a time bomb.
- `parso` — quarantine, risk 57 (static only: quarantine, risk 45); findings LLM.REVIEW.CLAIM, PKG.CODE.DELAYED_EXEC, PROV.PUBLISHER.UNLISTED — static DELAYED_EXEC on cache expiry (`file.stat().st_atime + _CACHED_FILE_MAXIMUM_SURVIVAL <= time.time()`), a time comparison; the reviewer added a medium claim on reading environment variables for the cache path.
- `pymongo` — block, risk 80 (static only: allow, risk 5); findings LLM.REVIEW.CLAIM, PROV.PUBLISHER.UNLISTED — reviewer only: three high claims (HTTP to the Azure/GCP metadata services for cloud auth, subprocess for daemonising); static risk was 5, the claims pushed it to block (80).
- `sentry-sdk` — block, risk 80 (static only: allow, risk 5); findings LLM.REVIEW.CLAIM, PROV.PUBLISHER.UNLISTED — reviewer only: three high claims (`git rev-parse` via subprocess, reading `SENTRY_DSN`, urllib3 network); static risk was 5, the claims pushed it to block (80). The SDK's whole purpose is to report over the network.

**HF chat templates flagged (final set): 4**
- `THUDM__chatglm3-6b` — quarantine, risk 52 (static only: quarantine, risk 47); findings LLM.CARD.MISSING, MODEL.CONFIG.AUTO_MAP, MODEL.CONFIG.AUTO_MAP_MISSING, MODEL.PARENT.UNIDENTIFIED, PROV.PUBLISHER.UNLISTED — tokenizer/config `auto_map` points at repo-shipped Python (needs trust_remote_code), plus missing card and unidentified parent; policy-correct to hold for review.
- `internlm__internlm2-chat-7b` — quarantine, risk 52 (static only: quarantine, risk 47); findings LLM.CARD.MISSING, MODEL.CONFIG.AUTO_MAP, MODEL.CONFIG.AUTO_MAP_MISSING, MODEL.PARENT.UNIDENTIFIED, PROV.PUBLISHER.UNLISTED — `auto_map` ships repo Python for the tokenizer (trust_remote_code); policy-correct to hold, vendor is well known.
- `moonshotai__Kimi-K2-Thinking` — quarantine, risk 64 (static only: quarantine, risk 59); findings LLM.CARD.MISSING, MODEL.CONFIG.AUTO_MAP, MODEL.CONFIG.AUTO_MAP_MISSING, MODEL.PARENT.UNIDENTIFIED, MODEL.TEMPLATE.UNPARSEABLE, PROV.PUBLISHER.UNLISTED — `auto_map` ships repo Python and the template did not parse (MODEL.TEMPLATE.UNPARSEABLE); held for review.
- `nvidia__NVIDIA-Nemotron-Nano-9B-v2` — quarantine, risk 65 (static only: quarantine, risk 60); findings LLM.CARD.MISSING, MODEL.PARENT.UNIDENTIFIED, MODEL.TEMPLATE.CONTENT_CONDITIONAL, PROV.PUBLISHER.UNLISTED — the real template switches on message content (`/think`, `/no_think` handling), which the content-conditional rule treats as a possible trigger.

**Intake timeouts on the final sets (the pipeline did not finish within 120 s, so there is no decision): 7**
- `black` — hangs: `package_taint._bind` never finishes (confirmed running >30 min on this package in the first attempt, then killed). Static scanner bug, not mine.
- `datasets` — stuck in `package_taint._bind` at 100 s, the same loop as `black`.
- `google-cloud-aiplatform` — very large package; still in `package_capabilities` file analysis at 100 s (slow, possibly not hung).
- `kubernetes` — very large package (thousands of generated files); still parsing files (`_pycode.iter_python`) at 100 s; slow, possibly not hung.
- `litellm` — very large package; still parsing files at 100 s; slow, possibly not hung.
- `torch` — very large package; still parsing files at 100 s; slow, possibly not hung.
- `transformers` — very large package; no scanner frame captured at 100 s; slow, possibly not hung.

**Policy blocks (benign pickles refused by `allow_pickle: false`): 5** `f_pkl_ok_defaultdict`, `f_pkl_ok_fraction_decimal`, `f_pkl_ok_compiled_re`, `f_pkl_ok_bytes_complex`, `f_pkl_ok_torch_zip_plain`

**Final-set decisions changed by the reviewer/worker** — true positives gained: `f_tool_mal_undeclared_delete` · false alarms introduced: `docutils`, `jedi`, `pymongo`, `sentry-sdk` · true positives lost: none · false alarms removed: none · outcome-only: `f_pkg_mal_pip_install_url`

## Read this before quoting a number

- The final synthetic corpus is **my own construction** (80 items, 6 categories): it tests generalisation to new techniques, not to adversaries who know the scanners. Intervals are wide; treat differences of a few items as noise.
- Real PyPI/HF artifacts are presumed benign. A flagged real package may be a true finding; each is listed above with the reason.
- The dev real-world sets were re-fetched here (top-PyPI snapshot 2026-10-01, HF `main` today), so they match the other session's procedure but not necessarily its exact bytes.
- LoRA detector: the only 'unseen' LoRA data would require training new adapters; none were trained for this run, so the final column has no LoRA number. The in-sample and dev numbers use the same held-out test split of one bank whose training recipe was tuned.
- Cost rows: 'busy time' is the reviewer LLM's wall time on a dedicated GPU; 'whole intake wall time' charges the GPU for the entire time an artifact is in intake. Weight-space and behaviour checks are not in these figures.
- Reviewer unit benchmark (separate, small, partly tuned): see `bench/reviewer.json` and the Reviewer section of `bench/results.md`.
