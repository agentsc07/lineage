# Dev-set results: before / after the precision changes

Generated 2026-10-26T06:59:00+00:00 · dev, CPU, no GPU worker, LINEAGE_OFFLINE=1 · policy `examples/policy.org.yaml` (allow ≤ 30, quarantine ≤ 70, block > 70)

**DEV set** = PyPI top 1-200 (wheels), 50 Hugging Face chat templates, `bench/corpus_holdout` (80 items). No other data was read while tuning.
**Flagged** = outcome `block`, or risk above the policy's allow threshold (as in `bench/run_bench.py`). **Policy block** = blocked only because `allow_pickle: false` forbids the pickle format with nothing dangerous inside; reported separately and not counted as a false positive.
**Before** = branch `precision` at its start (`scanner-fixes` merged). **After** = this branch. PyPI packages are reviewed diff-aware: each is compared with its previous release (fetched wheel-only).

## Headline

| | before | after |
|---|---|---|
| PyPI top-200 flagged | 134/200 (67%) | **0/200 (0%)** |
| HF chat templates flagged | 10/50 (20%) | 3/50 (6%) |
| held-out TPR | 75% | **100%** |
| held-out FPR (policy blocks excluded) | 15% | 0% |
| held-out policy blocks (pickle, `allow_pickle: false`) | 0 | 6 |

## Held-out corpus, per category

| category | malicious | TPR before | TPR after | benign | FPR before | FPR after | policy blocks |
|---|---|---|---|---|---|---|---|
| chat_template_backdoor | 6 | 83% | **100%** (6/6) | 6 | 0% | 0% | 0 |
| lookalike_name | 6 | 100% | **100%** (6/6) | 6 | 0% | 0% | 0 |
| mcp_tool_poisoning | 6 | 33% | **100%** (6/6) | 6 | 0% | 0% | 0 |
| package_payload | 10 | 60% | **100%** (10/10) | 10 | 0% | 0% | 0 |
| pickle_payload | 6 | 100% | **100%** (6/6) | 6 | 100% | 0% | 6 |
| swapped_tokenizer | 6 | 83% | **100%** (6/6) | 6 | 0% | 0% | 0 |

Held-out items still wrong after:

- none

Policy blocks (benign pickles refused by `allow_pickle: false`): `h_pkl_ok_ordered_dict`, `h_pkl_ok_numpy_array`, `h_pkl_ok_datetime_set`, `h_pkl_ok_torch_rebuild_ref`, `h_pkl_ok_plain_nested`, `h_pkl_ok_torch_zip_ordereddict`

## Real-world false-positive check, per category

| set | n | flagged before | flagged after | allow | quarantine | block |
|---|---|---|---|---|---|---|
| PyPI top-200 | 200 | 134 | **0** | 200 | 0 | 0 |
| HF chat templates | 50 | 10 | **3** | 47 | 3 | 0 |

### Which findings flagged PyPI packages (items affected)

| finding | before | after |
|---|---|---|
| PKG.CAP.OBFUSCATION | 125 | 0 |
| PKG.CAP.ENV_SECRETS | 97 | 0 |
| PKG.CAP.FILESYSTEM | 95 | 0 |
| PKG.CAP.DYNAMIC_EXEC | 74 | 0 |
| PKG.CAP.NETWORK | 67 | 0 |
| PKG.CAP.ENCODED_BLOB | 56 | 0 |
| PKG.CAP.SUBPROCESS | 51 | 0 |
| PKG.PROV.REPO_OWNER_MISMATCH | 26 | 0 |
| PKG.CODE.CREDENTIAL_EXFIL | 10 | 0 |
| PKG.CODE.BAIT_ON_RISKY_CODE | 5 | 0 |
| PKG.CODE.DELAYED_EXEC | 4 | 0 |
| PKG.HOOK.STARTUP_HOOK | 3 | 0 |
| PKG.TAINT.FILE_UPLOAD | 2 | 0 |
| PKG.CODE.REMOTE_EXEC_POSSIBLE | 1 | 0 |
| PKG.TAINT.ENCODED_EXEC | 1 | 0 |
| PKG.TAINT.ENV_EXFIL | 1 | 0 |

## Every remaining flag (3)

| artifact | outcome (risk) | findings | verdict |
|---|---|---|---|
| THUDM__glm-4-9b-chat | quarantine (47) | LLM.CARD.MISSING, MODEL.CONFIG.AUTO_MAP, MODEL.CONFIG.AUTO_MAP_MISSING | **DEFENSIBLE**: auto_map points the tokenizer at Python shipped in the repo (needs trust_remote_code). Holding it for review is the policy working; the vendor is well known. The 'code not in directory' finding is a harness artefact: only tokenizer_config.json was fetched. |
| internlm__internlm2_5-7b-chat | quarantine (47) | LLM.CARD.MISSING, MODEL.CONFIG.AUTO_MAP, MODEL.CONFIG.AUTO_MAP_MISSING | **DEFENSIBLE**: Same: auto_map tokenizer classes are repo-shipped Python (trust_remote_code). Correct to hold; 'missing files' is because the harness fetched only tokenizer_config.json. |
| moonshotai__Kimi-K2-Instruct | quarantine (47) | LLM.CARD.MISSING, MODEL.CONFIG.AUTO_MAP, MODEL.CONFIG.AUTO_MAP_MISSING | **DEFENSIBLE**: Same: auto_map TikTokenTokenizer is repo-shipped Python (trust_remote_code). Correct to hold; 'missing files' is a harness artefact. |

<details><summary>The 134 PyPI packages flagged before</summary>

aiobotocore, aiohttp, alembic, anthropic, anyio, attrs, azure-core, boto3, botocore, cffi, chardet, charset-normalizer, click, cloudpickle, colorama, coverage, cryptography, decorator, defusedxml, dill, distlib, dnspython, email-validator, fastapi, filelock, fonttools, fsspec, ghapi, gitdb, gitpython, google-api-core, google-auth, google-cloud-bigquery, google-cloud-core, google-cloud-storage, googleapis-common-protos, greenlet, grpcio, h2, hatchling, httpx, httpx2, huggingface-hub, identify, importlib-metadata, jinja2, jmespath, joblib, jsonschema, keyring, langchain, langchain-core, lxml, mako, markdown-it-py, matplotlib, mcp, msal, mypy, networkx, nodeenv, numpy, oauthlib, openai, openpyxl, opentelemetry-api, opentelemetry-exporter-otlp-proto-http, opentelemetry-instrumentation, opentelemetry-proto, opentelemetry-sdk, packaging, pandas, pillow, pip, platformdirs, pre-commit, prompt-toolkit, propcache, proto-plus, protobuf, psutil, pyarrow, pycparser, pydantic, pydantic-settings, pygments, pyjwt, pyopenssl, pyparsing, pytest, python-dateutil, python-discovery, python-dotenv, pytz, pyyaml, redis, regex, requests, requests-oauthlib, requests-toolbelt, rich, rsa, ruamel-yaml, s3fs, s3transfer, scikit-learn, scipy, setuptools, shellingham, six, soupsieve, sqlalchemy, starlette, tabulate, threadpoolctl, tiktoken, tokenizers, tqdm, typer, typing-extensions, typing-inspection, urllib3, uvicorn, uvloop, virtualenv, watchfiles, wcwidth, websocket-client, websockets, werkzeug, wheel, wrapt, yarl, zstandard

</details>

## Read this before trusting the numbers

- This is now a **dev** set: rules were tuned against it, so 0/200 and 100% TPR are not out-of-sample estimates. The validation commit measured the same held-out corpus at 52% TPR before the `scanner-fixes` merge; `before` here already includes those fixes (75%).
- Diff-aware review lowers anything the previous release already had. A package that shipped its payload in an earlier release is only caught by the combinations that are never lowered (credential exfiltration, fetch-and-run, decoded blob executed, hard advisories), or when the earlier release is itself reviewed.
- With no previous release (first release, offline) only combinations fire; a lone capability such as `subprocess` is a signal. The held-out malicious packages are all first releases, so they test exactly that mode.
- Test code in a wheel is excluded from combinations. The three template flags are `auto_map` custom tokenizer code, kept as quarantine by design.
- Run the real-world half on a fresh sample (PyPI ranks 201-400, other templates) before claiming the rate.

