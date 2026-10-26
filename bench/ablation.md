# Reviewer ablation

Generated 2026-10-26T08:50:18+00:00 · worker `http://127.0.0.1:8800` · reviewer `nvidia/NVIDIA-Nemotron-Nano-9B-v2` · full run · flagged = block or risk > allow threshold · Wilson 95% intervals.

Static-only = GPU worker off (deterministic scanners). Static+reviewer = worker on (reviewer LLM and the other deep checks the worker serves).

| set | n | static TPR | static FPR | +reviewer TPR | +reviewer FPR | decisions changed | latency added (mean / p95) | GPU-s per artifact |
|---|---|---|---|---|---|---|---|---|
| corpus | 131 (68 mal / 63 ben) | 90% (80%–95%) | 6% (2%–15%) | 91% (82%–96%) | 6% (2%–15%) | 3 | 1.16 s / 6.20 s | 0.59 |
| corpus_holdout | 80 (40 mal / 40 ben) | 100% (91%–100%) | 0% (0%–9%) | 100% (91%–100%) | 0% (0%–9%) | 1 | 1.32 s / 6.13 s | 1.12 |
| pypi_top200_dev | 200 (0 mal / 200 ben) | – | 0% (0%–2%) | – | 6% (3%–10%) | 12 | 4.30 s / 9.58 s | 4.31 |
| hf_templates | 50 (0 mal / 50 ben) | – | 6% (2%–16%) | – | 6% (2%–16%) | 0 | -0.00 s / 0.00 s | 0.00 |
| corpus_final | 80 (40 mal / 40 ben) | 68% (52%–80%) | 5% (1%–17%) | 70% (55%–82%) | 5% (1%–17%) | 2 | 1.43 s / 6.79 s | 1.22 |
| pypi_201_400 | 199 (0 mal / 199 ben) | – | 3% (1%–6%) | – | 5% (2%–8%) | 4 | 3.39 s / 9.01 s | 3.38 |
| hf_templates_final | 50 (0 mal / 50 ben) | – | 8% (3%–19%) | – | 8% (3%–19%) | 0 | -0.00 s / 0.00 s | 0.00 |

## corpus

- Reviewer called on 18 of 66 intake items; 38 LLM calls, 3202 generated tokens; 77.6 GPU-s total (4.31 per reviewed artifact); latency added on reviewed items 4.31 s on average.
- Risk scores changed on 22 items; lowered on 0 (must be 0: the worker may only raise).
- Flag raised (static: not flagged → with reviewer: flagged): `tool_mal_undeclared_network` (true positive gained)
- Flag lowered (static: flagged → with reviewer: not flagged): none
- Outcome changed, flag unchanged: `pkg_mal_ssh_key_theft` (quarantine→block), `pkg_mal_b64_exec` (quarantine→block)

## corpus_holdout

- Reviewer called on 21 of 68 intake items; 45 LLM calls, 3713 generated tokens; 89.9 GPU-s total (4.28 per reviewed artifact); latency added on reviewed items 4.29 s on average.
- Risk scores changed on 19 items; lowered on 0 (must be 0: the worker may only raise).
- Flag raised (static: not flagged → with reviewer: flagged): none
- Flag lowered (static: flagged → with reviewer: not flagged): none
- Outcome changed, flag unchanged: `h_pkg_mal_popen_setup` (quarantine→block)

## pypi_top200_dev

- Reviewer called on 168 of 200 intake items; 302 LLM calls, 33233 generated tokens; 863.0 GPU-s total (5.14 per reviewed artifact); latency added on reviewed items 5.12 s on average.
- Risk scores changed on 52 items; lowered on 0 (must be 0: the worker may only raise).
- Flag raised (static: not flagged → with reviewer: flagged): `cffi` (false positive introduced), `cryptography` (false positive introduced), `distlib` (false positive introduced), `fsspec` (false positive introduced), `numpy` (false positive introduced), `opentelemetry-sdk` (false positive introduced), `pre-commit` (false positive introduced), `protobuf` (false positive introduced), `pygments` (false positive introduced), `python-dateutil` (false positive introduced), `pyyaml` (false positive introduced), `ruamel-yaml` (false positive introduced)
- Flag lowered (static: flagged → with reviewer: not flagged): none
- Outcome changed, flag unchanged: none

## hf_templates

- Reviewer called on 0 of 50 intake items; 0 LLM calls, 0 generated tokens; 0.0 GPU-s total (0.00 per reviewed artifact); latency added on reviewed items 0.00 s on average.
- Risk scores changed on 50 items; lowered on 0 (must be 0: the worker may only raise).
- Flag raised (static: not flagged → with reviewer: flagged): none
- Flag lowered (static: flagged → with reviewer: not flagged): none
- Outcome changed, flag unchanged: none

## corpus_final

- Reviewer called on 20 of 68 intake items; 46 LLM calls, 4023 generated tokens; 97.3 GPU-s total (4.87 per reviewed artifact); latency added on reviewed items 4.87 s on average.
- Risk scores changed on 22 items; lowered on 0 (must be 0: the worker may only raise).
- Flag raised (static: not flagged → with reviewer: flagged): `f_tool_mal_undeclared_delete` (true positive gained)
- Flag lowered (static: flagged → with reviewer: not flagged): none
- Outcome changed, flag unchanged: `f_pkg_mal_pip_install_url` (quarantine→block)

## pypi_201_400

- Reviewer called on 139 of 199 intake items; 223 LLM calls, 25848 generated tokens; 672.8 GPU-s total (4.84 per reviewed artifact); latency added on reviewed items 4.84 s on average.
- Risk scores changed on 29 items; lowered on 0 (must be 0: the worker may only raise).
- Flag raised (static: not flagged → with reviewer: flagged): `docutils` (false positive introduced), `jedi` (false positive introduced), `pymongo` (false positive introduced), `sentry-sdk` (false positive introduced)
- Flag lowered (static: flagged → with reviewer: not flagged): none
- Outcome changed, flag unchanged: none

## hf_templates_final

- Reviewer called on 0 of 50 intake items; 0 LLM calls, 0 generated tokens; 0.0 GPU-s total (0.00 per reviewed artifact); latency added on reviewed items 0.00 s on average.
- Risk scores changed on 50 items; lowered on 0 (must be 0: the worker may only raise).
- Flag raised (static: not flagged → with reviewer: flagged): none
- Flag lowered (static: flagged → with reviewer: not flagged): none
- Outcome changed, flag unchanged: none
