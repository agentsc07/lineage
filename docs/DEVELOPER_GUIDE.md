# Developer guide: using artifacts your organisation has approved

For an engineer whose model, dataset, package or tool has been through Lineage. Replace `lineage-server` and the token with what your administrator gave you.

## 0. One-time setup (per machine)

```bash
pip install git+https://github.com/agentsc07/lineage.git     # provides the `lineage` command and `import lineage` (not published on PyPI)
# inside a clone of the repository instead:  uv sync
export LINEAGE_SERVER=https://lineage-server        # your registry
export LINEAGE_TOKEN=lg_...                         # your personal token (role: requester or approver). Never commit it
lineage pull <any approved artifact> ./x -e dev --pin   # the first pull pins the registry's public key in ~/.lineage/config.toml
```

The pinned key is what lets your machine tell a genuine registry attestation from a forged one. Confirm the key with your administrator the first time ("trust on first use"). Environments are `dev`, `staging`, `prod`; an artifact approved for one is not automatically approved for another.

## 1. Get something approved

1. Open the dashboard, **Intake**. Pick the **Type** yourself (it is not detected).
2. Give a **source** (`hf:org/name@<commit>`, `hf-dataset:org/name`, `pypi:name==1.2.3`) **or upload** a file/archive. If you upload something that is a copy of a hub repository, fill **Claimed origin** with `hf:org/name@<commit sha>`: Lineage then compares every file with the hub's published hash. Without it, trust stays `unknown`.
3. Optional claims (name, version, base model as a Hugging Face repo id, licence, ...): they are recorded as declared and can only add risk.
4. Press **Start intake**. A verdict appears: **Allow**, **Allow with conditions**, **Quarantine** (a different person must approve), **Block**.
5. Quarantined: ask an approver. They open **Approvals**, read the findings, and approve with a reason and an expiry. You cannot approve your own request.
6. A blocked artifact with a "hard block" cannot be approved. Fix the artifact (for example remove the pickle file, re-download from the hub) and submit again.

## 2. Use it

| You are using a... | Do this |
|---|---|
| **model** | `lineage pull triage-base ./models/triage-base -e prod` then in Python `import lineage; model = lineage.load("./models/triage-base", env="prod")`. Or one step: `from lineage import LineageAutoModel; LineageAutoModel.from_pretrained("hf:org/name", env="prod")` |
| **dataset** | `lineage pull hf-dataset:org/name ./data/x -e prod` then `lineage load-check ./data/x -e prod` before you read it (`lineage.load` returns the verified path for non-model folders) |
| **package** | `pip install --index-url http://you:$LINEAGE_TOKEN@lineage-server/simple/ acme-llm`. Only approved versions exist on that index; pip picks the newest approved one. Put it in `pip.conf` or `uv`'s `index-url` so it is the only index |
| **Hugging Face tooling** | `export HF_ENDPOINT=http://lineage-server HF_TOKEN=$LINEAGE_TOKEN`; `from_pretrained("org/name")` then downloads only approved models |
| **MCP tool** | connect your agent to the Lineage gateway instead of the tool directly; it blocks a tool whose description or code changed after approval |

By name: `lineage pull acme-llm ...` finds the newest artifact usable in that environment whose name or source repo is `acme-llm`; use `pypi:acme-llm==1.4.0` for an exact version and `lp:<id>` for an exact artifact.

## 3. Check something you already have

```bash
lineage load-check ./models/triage-base -e prod     # exit 0 = ok; exit 1 = refused, with every reason
```

It re-hashes every file, verifies the registry's signature against your pinned key, checks expiry, and asks the registry **now** whether it was revoked (also a revoked parent) or its decision changed. In `prod` it fails closed if the registry cannot be reached; `dev` allows 24 h, `staging` 6 h with a cached attestation.

Typical refusals: `no attestation` (you never ran `lineage pull`); `attestation is for dev, not prod`; `hash mismatch: <file>` (the file changed after the pull); `artifact is revoked`; `registry reports a revoked ancestor`; `signature does not verify against the pinned registry key` (the registry was rebuilt: re-pin with `--pin`).

## 4. Train a model and keep the lineage

```bash
lineage keygen --name my-team --dir keys                 # once: keys/my-team.key (private), keys/my-team.pub
# give your administrator keys/my-team.pub (or publish it: --publish --scope 'upload:*') to be listed as a trusted publisher
lineage pull base-model ./base -e prod
lineage pull hf-dataset:org/instructions ./data -e prod
lineage run --key keys/my-team.key --name triage-v2 --version 1.0.0 -- python train.py
```

In `train.py`, load inputs through Lineage so they are recorded:

```python
import lineage
base = lineage.load("./base", env="prod")          # verified; this is what records the parent
rows = open("./data/instructions.jsonl")            # plain file reads are recorded by lineage run
# ... train ...
# save outputs normally (model.safetensors, config.json)
```

`lineage run` records every file the process opens (as inputs, with hashes), the installed packages (`pip freeze`, plus packages under `PYTHONPATH`), the artifacts verified by `lineage.load` (as parents) and the outputs; it writes a signed `<output>.passport.json` beside each output. Submit the output folder **with that passport** to Lineage. If your key is a trusted publisher, the recorded parents, inputs and packages become edges in the lineage graph.

What it does not do: it does not stop you from using an unapproved input, and it cannot see data read by native libraries that bypass Python's `open` (weights read by `safetensors` directly, `pyarrow`/`datasets` parquet). Load those through `lineage.load` or `lineage pull` + `load-check`, or the parent will be missing from the graph.

## 5. Publish your own artifact to others

```bash
lineage sign ./my-model --type model --name my-model --version 1.0.0 --key keys/my-team.key --hub huggingface --repo my-org/my-model
lineage keygen --name my-team --dir site --publish --scope 'hf:my-org/*'   # makes site/.well-known/lineage-keys.json
```

Host `lineage-keys.json` at `https://<your domain>/.well-known/lineage-keys.json` and ship the passport next to the files. A customer verifies with `lineage verify passport.json --artifact ./my-model --from https://<your domain>`, and adds your public key to their policy's `trusted_publishers` with the scope you may sign for.

## 6. Troubleshooting

| You see | Cause | Fix |
|---|---|---|
| `ModuleNotFoundError: No module named 'lineage'` (macOS) | the editable install file is hidden | `export PYTHONPATH=<repo>` or `uv sync --reinstall` |
| `a valid API token is required` | `LINEAGE_TOKEN` empty or from another database | re-export the token; the demo creates new tokens each run |
| `no attestation for ...` | the folder was not created by `lineage pull` | pull it |
| `not admitted for prod (404 ...)` | nobody approved it for `prod` (or it is quarantined) | ask an approver; or pull for `-e dev` |
| `Did not run: acquire ... HTTP 404` on intake | the hub does not have that repo (or the demo hub is the fake one; use `LINEAGE_DEMO_REAL_HUB=1`) | check the id; `hf:` is a model repo, `hf-dataset:` a dataset repo |
