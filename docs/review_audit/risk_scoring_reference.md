# Risk scoring reference

Commit `24af4c9`. Sources: `lineage/risk.py`, `lineage/inspect/_common.py`, `lineage/intake/inspectors.py::make_finding/not_run`, `lineage/policy/engine.py`, `lineage/schemas/policy.py`, `examples/policy.org.yaml`.

## 1. Authoritative policy at runtime

The server installs `LINEAGE_POLICY` (default `examples/policy.org.yaml`) into the `policy_state` table **on first start only** (`lineage_server/app.py`, `policy_store.bootstrap`). After that the policy comes from the database (`get_policy` dependency); changes need a 2-of-3 role-signed update (`lineage_server/tuf.py`, `PUT /policy`). The demo writes its own copy (`examples/demo_helpers.py::demo_policy`: shipped policy plus the Apollo trusted publisher). `PolicyPack.unrun_checks` defaults to `{default: {dev: info, staging: medium, prod: high}}` if a policy omits it. The `Policy` page in the dashboard is read-only-ish and its signatures were noted as fake in the handoff; do not demo editing.

## 2. Formulas

```
finding_points(f)  = 0 if (f.source == "llm" and not f.grounded) else max(0, f.score)
group_advisories   : two or more PKG.OSV.* findings with severity != info collapse into ONE PKG.OSV.GROUP finding, score = weight of the worst severity
risk_score         = min(100, sum(finding_points over group_advisories(findings)) + TRUST_PENALTY[trust_level])
TRUST_PENALTY      = unknown 15, origin_verified 5, signed 0, recorded 0
eff_allow          = min(policy.thresholds.allow, env.max_risk)          # "production allow limit"
```

`Finding.score` is a separate field from `severity`. By default `score = SEVERITY_WEIGHT[severity]` (`make_finding`), but it is overridden in these places:

| Override | Where | Effect |
|---|---|---|
| `PROV.COOLDOWN.UNVERIFIED` | `inspectors.py::release_age` | medium but **score 0** (engine adds a quarantine reason instead) |
| `CHECK.NOT_RUN.*` | `engine.apply_unrun_costs` | severity from `policy.unrun_checks[name][env]`, then `score = SEVERITY_WEIGHT[severity]` (re-applied idempotently at each stage and again at S6 and in `decide`) |
| LLM claim with no static corroboration and no purpose mismatch (precise mode, default) | `llm_review/client.py::_to_finding` | `info`, score 0 |
| `LLM.*.UNGROUNDED*` | `claims_to_findings`, client | info, score 0, `grounded=False` |
| Combination already present in previous release | `package_capabilities._already_there` | info, score 0 (except `PKG.COMBO.CREDENTIAL_EXFIL`/`FETCH_AND_RUN`) |
| New start-up hook vs old | `hook_findings` | old hook = info |
| Schema bound | `Finding.score` is `0..40` | no finding exceeds 40 |

Severity weights: `info 0`, `low 5`, `medium 12`, `high 25`, `critical 40`.

## 3. Aggregation rules (answers)

1. **Is NOT_RUN always penalised?** No. It is priced by `policy.unrun_checks`; with the shipped policy, `dev` prices most as `info` = 0 points. `ACQUIRE` is `critical` in every environment and also a **hard block**. Experiment (tiny model, no card, offline): dev → all five NOT_RUN were `info` 0 pts; prod → PARENT_ID +12, WEIGHT_BACKDOOR +12, BEHAVIOUR_DIFF +12, LLM_REVIEW +25.
2. **Configurable?** By check name and environment (`unrun_checks[NAME][env]`), with a `default` row. Not by artifact type, and not by stage. A name with no entry uses `default`.
3. **Severity independent of points?** Technically yes (separate `score` field) but in practice they are tied by `make_finding`/`apply_unrun_costs`, except the overrides in §2.
4. **Summed, capped, deduplicated?** Summed, capped at 100. Only advisories are grouped. There is **no deduplication across checks**: if two scanners flag the same line, both count. (`hook_findings`/`combos` do avoid duplicating each other's output internally; not a global rule.)
5. **Same issue from multiple checks:** each finding adds its own points. Example: the demo poisoned dataset got +25 `DATA.TRIGGER.BEHAVIOUR` and +25 `DATA.DIFF.NEW_TOKENS` for the same 60 rows.
6. **Can an LLM result change the score?** Only upward. Grounded LLM findings add `score`; ungrounded add 0. LLM findings cannot remove or lower anything.
7. **Rules that force quarantine/block regardless of score** (`engine.hard_blocks`, `decide`):
   - Hard block (non-overridable): `INTEGRITY.FETCH_MISMATCH`; `PROV.ORIGIN.MODIFIED` (only in staging/prod); `PROV.SIGNATURE.INVALID`; `INTEGRITY.HASH_MISMATCH`; `PROV.PARENT.REVOKED`; `CHECK.NOT_RUN.ACQUIRE`; `PKG.OSV.MAL*`; pickle when `allow_pickle=false` (flagged as a `policy block:`); banned capability match; blocked publisher.
   - Soft (a live approval can accept them): cooldown not met (quarantine); `PKG.OSV.*` above `max_vuln_severity[env]` (block); `IDENTITY_IDS` critical → block, high → quarantine; `DATA.PII*` when `pii_allowed=false` (block); `POLICY.LICENCE.NOT_ALLOWED` (quarantine); trust below `env.min_trust` (quarantine); `require_human_approval` (quarantine).
   - `policy_expired` → at least quarantine.
8. **"Production allow limit":** `eff_allow = min(thresholds.allow (30), env.max_risk (prod 25))` = **25**. Decision: score > `thresholds.quarantine` (70) → block; else score > `eff_allow` → quarantine (headline `RANK_RISK` if any critical finding scores, else the weakest `RANK_RISK_BAND`). The decision text reads "risk N > 25 (prod allow limit)". Dev: min(30, 70) = 30; staging: min(30, 40) = 30.
9. **Approval, separation of duties, expiry vs risk:** an approval is a policy exception with `expires` (`service.approve` builds a `PolicyException`; `decide` treats a live exception as accepting all *soft* reasons → `allow_with_conditions`). It cannot override `floor` (hard blocks, expired policy). `service.approve` re-runs `decide` with the exception and refuses (`ApprovalRefused`) if the result would still be block/quarantine. The risk number is unchanged by approval. Separation of duties is enforced in `routes/decisions.py::approve`: the requester recorded in `artifact_meta.requester` cannot approve. Expired approvals: `decide` lists "exception by X expired" and the monitor re-evaluates lapsed approvals (`monitor.py`).
10. **Defaults vs database overrides:** see §1. No per-request override exists.

UI vs backend: the dashboard shows `Decision.risk_score` and finding scores from the backend; I found no separate score calculation in the frontend (grep of `dashboard/src` for score math not exhaustive: **UNVERIFIED**). One backend inconsistency: `_build_passport` stores `risk_score(findings, trust)` and `decide` recomputes it with `apply_unrun_costs`; both use the same function, so they match.

## 4. Policy thresholds and tables (shipped `examples/policy.org.yaml`)

| Item | Value |
|---|---|
| environments | dev `min_trust unknown, max_risk 70`; staging `origin_verified, 40`; prod `origin_verified, 25` |
| thresholds | allow 30, quarantine 70 (above 70 = block) |
| require_human_approval | `tool`, `model:prod` |
| cooldown_days | package 3, model 7, dataset 7, tool 7 |
| max_vuln_severity | prod medium, dev high |
| banned_capabilities | network_at_install, startup_hook, dynamic_exec_of_remote_code |
| model_files.allow_pickle | false |
| data.pii_allowed | false |
| unrun_checks.default | dev info, staging medium, prod high |
| ACQUIRE | critical / critical / critical |
| WEIGHT_BACKDOOR, PARENT_ID, BEHAVIOUR_DIFF | dev info, staging low, prod medium |
| POLICY_CHECK | dev info, staging info, prod low |
| any other NOT_RUN (LLM_REVIEW, OSV, PKG_METADATA, NOTARY, PARENT_FETCH, PARQUET, FULL_SCAN, TAINT_PARTIAL, DATASET_V2, DATASET_DIFF, ...) | `default`: dev info, staging medium, prod high |

Note `NOT_RUN` names come from `not_run(name, ...)` → id `CHECK.NOT_RUN.<NAME>`; `apply_unrun_costs` keys on the first dotted segment after the prefix.

## 5. Status codes the pipeline can emit for a check

There is no PASS/FINDING/NOT_RUN/ERROR enum in code. The real statuses are: findings (any severity, `info` = nothing wrong or informational); `CHECK.NOT_RUN.<NAME>` (could not run; priced); `SCANNER.ERROR.<NAME>` (scanner crashed, medium); `INTAKE.STAGE.ERROR` (stage crashed, high); stage event status `completed|skipped|failed`. A clean run of a quiet scanner is an **empty list** (that is why `tests/test_no_silent_skip.py` keeps an explicit `QUIET_WHEN_CLEAN` list).

## 6. Worked example: 29, 54 and 66

Reproduced by running the real pipeline/server (offline, no GPU, no key), prod, model fetched from the demo hub (`origin_verified`):

| Run | Findings that score | Sum | + trust penalty | Risk | Decision |
|---|---|---|---|---|---|
| First intake of `hf:apollo-health/triage-base` (demo step 2, executed) | `CHECK.NOT_RUN.PARENT_ID` medium 12; `WEIGHT_BACKDOOR` medium 12; `BEHAVIOUR_DIFF` medium 12; `LLM_REVIEW` high 25 | 61 | origin_verified 5 | **66** | quarantine: "human approval required by policy"; secondary "risk 66 > 25 (prod allow limit)" |
| Same model again, after a copy is admitted (executed): parent is `MODEL.PARENT.IDENTICAL` (info 0) | `WEIGHT_BACKDOOR` 12; `BEHAVIOUR_DIFF` 12; `LLM_REVIEW` 25 | 49 | 5 | **54** | quarantine |
| Same, with the LLM review **running** and producing no scoring finding (**arithmetic only; not executed here**) | `WEIGHT_BACKDOOR` 12; `BEHAVIOUR_DIFF` 12 | 24 | 5 | **29** | quarantine (29 > 25, and human approval required) |

So **29 = 12 (WEIGHT_BACKDOOR NOT_RUN, prod medium) + 12 (BEHAVIOUR_DIFF NOT_RUN, prod medium) + 5 (trust penalty for `origin_verified`)**. There are no other points *if* the other checks emit only `info`/0. Caveats: (a) a model/dataset **without a card** adds `LLM.CARD.MISSING` (low, +5), giving 34; (b) a parent not found adds PARENT_ID +12; (c) any `LLM.CARD.CLAIM` that grounds adds its severity weight. The 54 and 66 rows were reproduced exactly; the 29 row was not, because it needs a working LLM backend (no API key in this environment). In the 29 case the decision is still quarantine: 29 > 25 and `model:prod` requires a human; after bob's approval the number stays 29 and the outcome becomes `allow_with_conditions`.

Other executed data points: tiny model, no origin, no card, prod: 12 (`ORIGIN.UNCLAIMED`) + 12 + 12 + 12 + 25 + trust unknown 15 = **88 → block** (>70); same in dev: 12 + 15 = **27 → quarantine** (cooldown unverifiable). Compromised package demo: 100 (capped) → block.
