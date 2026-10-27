# Real-world false-alarm rate after the refactor (static only)

Presumed-benign real artifacts: the 200 most downloaded PyPI wheels, wheels ranked 201-400, and 100 Hugging Face chat templates (50 dev, 50 final), re-fetched on 28 Oct 2026 with `bench/fetch_realworld.py`, `bench/fetch_final.py`, `bench/fetch_previous.py` and `bench/make_realworld_sets.py`, then run with `bench/run_realworld_after.py` (no GPU, no API key, unrun checks priced at info). **The sets are not byte-identical to the frozen run**: the top-PyPI list and package versions moved since, one package (`playwright`) needed a retry, and `fetch_previous` timed out for some final-set packages, so a few have no previous-release baseline. A flagged real package may be a true finding; these numbers are false-alarm rates, not FPR against verified-clean data.

| set | frozen (static only) | first re-run (before the rule fixes below) | after the rule fixes |
|---|---|---|---|
| PyPI top 1-200 (dev) | 0/200 | 18/200 | 2/200 (+1 timed out) |
| HF chat templates (dev, 50) | 3/50 | 3/50 | 3/50 |
| PyPI 201-400 (final) | 5/199 | 20/199 (+3 timed out) | 8/199 (+5 timed out) |
| HF chat templates (final, 50) | 4/50 | 5/50 | 5/50 |

## What the first re-run showed, and what changed

The first re-run was 18/200 on the dev PyPI set (frozen 0/200). Sixteen of the 18 came from the three new package rules of R4.2 firing on ordinary library code (`PKG.RULE.IMPORT_HOOK` on `six`, `pytest`, `pip`, `importlib-metadata`, `wrapt`, `virtualenv`, `distlib`, `botocore`, `keyring`, `editables`, ...; `PKG.RULE.OBFUSCATED_TARGET` on `dnspython` and `scipy`; `PKG.RULE.ATEXIT_EFFECT` on `msal`). They are now precise by default (`DECISIONS.md`, Final pass G4):
- `IMPORT_HOOK` is `info` unless the registered finder/loader calls the network, a process or code execution, or the hook is installed from a startup file. A loader's `exec(code, module.__dict__)` is the loader contract and does not count (`grpcio-tools`).
- `OBFUSCATED_TARGET` needs a name built only from string literals that spells a dangerous module or function; names built from variables are dynamic dispatch.
- `ATEXIT_EFFECT` needs a network or process effect at exit; a file write alone (a cache, a log) is `info`.
- `MODEL.TEMPLATE.HIDDEN_TOOL_CALL` ignores placeholder names that document the call format (`function_name`; Falcon3).

## Every remaining false alarm

| set | artifact | rule | note |
|---|---|---|---|
| PyPI top 1-200 (dev) | `jsonschema` | `PKG.NEW.SUBPROCESS` | quarantine, risk 35 |
| PyPI top 1-200 (dev) | `nodeenv` | `PKG.NEW.CREDENTIAL_PATH` | quarantine, risk 35 |
| PyPI top 1-200 (dev) | `pandas` | none | timed out after 120 s: no decision, not counted as flagged |
| HF chat templates (dev, 50) | `THUDM__glm-4-9b-chat` | `MODEL.CONFIG.AUTO_MAP`, `MODEL.CONFIG.AUTO_MAP_MISSING` | quarantine, risk 52 |
| HF chat templates (dev, 50) | `internlm__internlm2_5-7b-chat` | `MODEL.CONFIG.AUTO_MAP`, `MODEL.CONFIG.AUTO_MAP_MISSING` | quarantine, risk 52 |
| HF chat templates (dev, 50) | `moonshotai__Kimi-K2-Instruct` | `MODEL.CONFIG.AUTO_MAP`, `MODEL.CONFIG.AUTO_MAP_MISSING` | quarantine, risk 52 |
| PyPI 201-400 (final) | `databricks-sdk` | `PKG.CODE.BAIT_ON_RISKY_CODE` | quarantine, risk 50 |
| PyPI 201-400 (final) | `debugpy` | `PKG.HOOK.STARTUP_HOOK` | block, risk 50 |
| PyPI 201-400 (final) | `google-cloud-aiplatform` | none | timed out after 120 s: no decision, not counted as flagged |
| PyPI 201-400 (final) | `google-genai` | `PKG.CODE.BAIT_ON_RISKY_CODE` | quarantine, risk 50 |
| PyPI 201-400 (final) | `grpcio-tools` | `PKG.RULE.IMPORT_HOOK` | quarantine, risk 35 |
| PyPI 201-400 (final) | `litellm` | none | timed out after 120 s: no decision, not counted as flagged |
| PyPI 201-400 (final) | `onnxruntime` | `PKG.CODE.BAIT_ON_RISKY_CODE` | quarantine, risk 50 |
| PyPI 201-400 (final) | `paramiko` | `PKG.CODE.DELAYED_EXEC` | quarantine, risk 50 |
| PyPI 201-400 (final) | `parso` | `PKG.CODE.DELAYED_EXEC` | quarantine, risk 50 |
| PyPI 201-400 (final) | `sympy` | none | timed out after 120 s: no decision, not counted as flagged |
| PyPI 201-400 (final) | `torch` | none | timed out after 120 s: no decision, not counted as flagged |
| PyPI 201-400 (final) | `tornado` | `PKG.COMBO.OBFUSCATED_PAYLOAD` | quarantine, risk 50 |
| PyPI 201-400 (final) | `transformers` | none | timed out after 120 s: no decision, not counted as flagged |
| HF chat templates (final, 50) | `THUDM__chatglm3-6b` | `MODEL.CONFIG.AUTO_MAP`, `MODEL.CONFIG.AUTO_MAP_MISSING` | quarantine, risk 52 |
| HF chat templates (final, 50) | `internlm__internlm2-chat-7b` | `MODEL.CONFIG.AUTO_MAP`, `MODEL.CONFIG.AUTO_MAP_MISSING` | quarantine, risk 52 |
| HF chat templates (final, 50) | `moonshotai__Kimi-K2-Thinking` | `MODEL.CONFIG.AUTO_MAP`, `MODEL.CONFIG.AUTO_MAP_MISSING` | quarantine, risk 52 |
| HF chat templates (final, 50) | `nvidia__NVIDIA-Nemotron-Nano-9B-v2` | `MODEL.TEMPLATE.CONTENT_CONDITIONAL` | quarantine, risk 65 |
| HF chat templates (final, 50) | `tiiuae__Falcon3-7B-Instruct` | `MODEL.TEMPLATE.HIDDEN_TOOL_CALL` | quarantine, risk 40 |

New relative to the frozen run, by rule: `PKG.NEW.SUBPROCESS` (`jsonschema`) and `PKG.NEW.CREDENTIAL_PATH` (`nodeenv`) are diffs against the previous release (an existing rule; these versions are newer than the frozen snapshot); `PKG.HOOK.STARTUP_HOOK` on `debugpy` is an existing rule that fires because that package's previous release was not fetched; `PKG.COMBO.OBFUSCATED_PAYLOAD` on `tornado` is an existing rule; `PKG.RULE.IMPORT_HOOK` on `grpcio-tools` and `MODEL.TEMPLATE.HIDDEN_TOOL_CALL` on `tiiuae__Falcon3-7B-Instruct` were new-rule false alarms found in this pass and fixed after the table above was measured (re-checked directly on those two artifacts, not by a full re-run). The other flagged items (`databricks-sdk`, `google-genai`, `onnxruntime`, `paramiko`, `parso`, the `trust_remote_code` chat-template repos, Nemotron-Nano) are in the frozen list too.

After the last two fixes, the three package rules and the template rule were scanned directly over all 399 packages and 100 templates (not through intake): `grpcio-tools` is now `info`, no template raises `HIDDEN_TOOL_CALL`, and the only scored `PKG.RULE.*` hit left is `PKG.RULE.ATEXIT_EFFECT` on `torch` (a network or process call in an exit handler; `torch` timed out in intake above, so it is not in the counts and would add one flagged package if it finished).

Not re-run end to end after the last two fixes: a full pass over the four sets takes about 25 minutes (`uv run python -m bench.run_realworld_after`).
