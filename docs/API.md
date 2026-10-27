# Lineage API contracts

Source: BUILD_PLAN §2.5 (server) and §2.6 (GPU worker). Request/response bodies are the Pydantic models in `lineage/schemas/artifact.py` (server) and `lineage/schemas/gpu.py` (GPU worker). Changing this file or those models needs `CONTRACT CHANGE:` in the commit message.

All requests except `/healthz` need `Authorization: Bearer <token>` (roles: requester, approver, admin, auditor; `LINEAGE_REQUIRE_AUTH=0` disables this for local development). The approver of a decision is the authenticated user and cannot be the user who requested the intake. All bodies are JSON. Passport ids look like `lp:<sha256>` and are used verbatim in paths. Passports are serialised with their in-toto field names (`_type`, `predicateType`).

## 1. Server API (`lineage_server`, default `http://127.0.0.1:8000`)

| Method | Path | Request | Response | Purpose |
|---|---|---|---|---|
| POST | `/uploads` | multipart `file` | `UploadReceipt {upload_id, filename, size}` | Send a file or archive (size cap `LINEAGE_MAX_UPLOAD_MB`); role `requester` |
| POST | `/intake` | `IntakeRequest {artifact_type, source, environment, claimed_origin?, claims?}` (`ref` only with `LINEAGE_DEV_LOCAL_PATHS=1`) | `IntakeJob {job_id, events_url}` | Start intake from `upload:<id>`, `hf:<repo>[@rev]`, `hf-dataset:<repo>[@rev]`, `pypi:<name>==<ver>`, `mcp:upload:<id>`; progress streams on `/events/{job}` |
| POST | `/jobs/{job_id}/stream-ticket` | any signed-in user | `{ticket, job_id, expires_in: 60}` | A 60-second ticket for this one job's stream. The API token is never accepted in a URL (no `?token=`) |
| GET | `/events/{job}` | bearer, or `?ticket=` for this job only | SSE of `StageEvent` | One `data:` line per stage transition (S1–S7); the S6 event carries the `Decision`. A ticket opens only this route for this job |
| GET | `/artifacts` | – | `Artifact[]` | Catalogue |
| GET | `/artifacts/{id}` | – | `ArtifactDetail {artifact, passport, findings, decision}` | Detail |
| POST | `/passports` | `SignedPassport` | `PassportReceipt {passport_id, log_index}` | Register a signed passport |
| GET | `/passports/{id}` | – | `SignedPassport` | Fetch |
| GET | `/passports/{id}/verify` | – | `VerifyResult` | Signature, chain, revocation |
| POST | `/decisions/{id}/reject` | approver | body `{reason}` -> `{artifact_id, status: rejected, actor, reason}` | Refuse a pending (quarantined) request. Not a revocation: nothing is revoked and no descendant changes; the actor and reason are recorded (table `rejections`, Merkle log kind `rejection`). The requester cannot reject their own request (403); an admitted artifact (409, use revoke) or a hard block (409) cannot be rejected |
| GET | `/graph/{id}?direction=up\|down&collapse=true` | – | `Graph {root, direction, nodes, edges}`; node adds `version`, `advisories[]`, `group_members[]`; edge adds `evidence` (fetched\|signed\|recorded\|declared\|inferred-from-weights\|sbom) | react-flow data; edges run parent → child. By default each artifact's un-advised SBOM packages (3 or more) fold into one `sbom-group:` node; `collapse=false` returns every node |
| POST | `/revoke/{id}?reason=` | approver | `RevokeResult {revoked, reason, blast_radius[]}` | Revoke; returns every flagged descendant |
| GET | `/policy` | – | `PolicyState` | Current policy pack, version, signatures, expiry |
| PUT | `/policy` | `PolicyUpdate {policy, signatures[], expires_at}` | `PolicyState` | Requires 2-of-3 role signatures (`owner`, `security`, `compliance`), TUF-style |
| POST | `/decisions/{id}/approve` | `ApprovalRequest {approver, reason, expires}` | `Decision` | Human approval |
| GET | `/attestations/{id}?env=` · `/attestations?digest=&env=` | – | `SignedAttestation {attestation{artifact_id, digest, files, outcome, environment, trust, policy_version, issued_at, expires_at, revoked}, signature, key_id}` | Registry-signed statement that the artifact may be used in `env` (issued from the latest decision, approvals and revocations) |
| GET | `/attestations/{id}/status?env=` | – | `AttestationStatus {artifact_id, environment, revoked, ancestor_revoked[], current_outcome, usable}` | The registry's answer now: revoked, a revoked ancestor, or a decision that is no longer allow. `load()` asks this before trusting a cached attestation |
| GET | `/registry-key` | – | `{key_id, public_key}` | Key attestations are signed with; clients pin it |
| GET | `/store/{id}/files/{path}?env=` · `/store/{id}/manifest` · `/lookup?source=` | – | bytes / `SignedAttestation` / `{artifact_id,name,version}` | Admitted bytes, served only while the attestation for `env` allows them |
| GET | `/simple/` · `/simple/{name}/` · `/files/{sha256}/{filename}` | – | PEP 503 HTML / wheel | Package index serving only admitted wheels, pinned by hash; token's environment |
| GET | `/whoami` | – | `{name, email, roles[], env, auth_required}` | The signed-in user |
| GET | `/trusted-publishers` | – | `TrustedPublishers {publishers[{name,key_id,key,scope[],revoked}], revoked_keys[], bootstrap_keys[]}` | Signing keys the active policy trusts and the sources each may speak for (read-only; change it with `PUT /policy`) |
| GET | `/log` | – | `MerkleLog {size, root, entries[]}` | Append-only Merkle log |
| GET | `/log/proof/{id}` | – | `InclusionProof {index, leaf_hash, path[], root, size}` | Inclusion proof for a log ref |
| POST | `/monitor/tick` | – | `MonitorTick {checked, alerts[], ts}` | Re-check advisories; alerts carry the blast radius |
| GET | `/monitor/latest` | – | `MonitorTick \| null` | Latest tick that raised alerts (else latest tick; null before any tick) |
| GET | `/artifacts/{id}/view` | – | `ArtifactView {merkle_root, claimed_origin, files[{path,size,sha256,origin: matching\|changed\|missing\|extra\|unchecked}], facts[{key,value,provenance,source}], creator_passport{present,claimed_publisher,key_id,signature,key_status,bytes_match}, finding_classes{id: hard_block\|policy_dependent\|scored}, decision, requester, hard_block, next_action, pull_command, pull_command_first_use}` | What the intake page shows, from what intake persisted |
| GET | `/jobs/{job_id}` | – | `{job_id, requester, artifact_type, environment, label, created_at, done, artifact_id}` | A reloaded page: what the job was (events replay from SQLite at `/events/{job_id}`) |
| GET | `/limits` | – | `{max_upload_mb, max_fetch_mb, max_archive_files, accepted[]}` | The server's real caps |
| GET | `/attestations/{id}/view?env=` | – | `{attestation: SignedAttestation, signature_ok, registry_key_id, verified_by}` | The attestation with the registry's own check of its signature (clients verify with the key they pinned) |
| GET | `/healthz` | – | `{"status": "ok"}` | Liveness |

Status: the skeleton returns mock data (`lineage_server/mock.py`) that validates against these models. Track B replaces it.

### Core models

- `Finding {id, title, severity, category, stage, evidence[], score 0–40, source, grounded}`
- `Decision {artifact_id, environment, outcome, reasons[], conditions[], risk_score, trust_level, findings[], policy_version, decided_at, approver?}`; `outcome` is `allow | allow_with_conditions | quarantine | block`
- `StageEvent {job_id, stage S0–S7, name, status started|completed|skipped|failed, findings[], message, decision?, elapsed_ms?, ts}` (`elapsed_ms`: server-measured, on the finishing event of a stage)
- `Artifact.status`: `submitted | quarantined | admitted | admitted_with_conditions | blocked | rejected | revoked` (rejected: a pending request was refused by an approver; revoked: an admitted artifact was withdrawn)
- `passport_id = "lp:" + sha256(canonical_json(passport))`; canonical JSON is sorted keys, no whitespace, UTF-8, datetimes as UTC ISO-8601. The signature is not part of the id.

## 2. GPU worker API (`gpu_worker`, port `:8800`, runs on Brev)

| Method | Path | Request → Response |
|---|---|---|
| POST | `/review/code` | `ReviewCodeRequest {purpose, capabilities[], slices[{file,start,end,code}], diff?}` → `ReviewResponse {claims[{text,file,line,api,severity}], verdict}` |
| POST | `/review/card` | `ReviewCardRequest {card_text, measured{}}` → `ReviewResponse` |
| POST | `/weights/parent` | `ParentRequest {model_path}` → `ParentResponse {parent, similarity, changed_layers[]}` |
| POST | `/weights/spectral` | `SpectralRequest {model_path, parent}` → `SpectralResponse {score, per_layer{}}` |
| POST | `/behaviour/diff` | `BehaviourDiffRequest {child, parent, probe_set}` → `BehaviourDiffResponse` (divergence report) |
| POST | `/behaviour/claims` | `BehaviourClaimsRequest {model, claims[]}` → `BehaviourClaimsResponse` (measured vs claimed) |
| POST | `/notary/certify` | `NotaryCertifyRequest {model_path}` → `NotaryCertificate` (hidden-test certificate) |
| POST | `/notary/check` | `NotaryCheckRequest {model_path, cert_id}` → `NotaryCheckResponse` (spot-check) |

`verdict` is `benign | suspicious | malicious`.

**Fallback.** If the GPU worker is unreachable, Inspector modules return an `info` Finding ("deep check skipped") and the pipeline continues. The demo must never crash.
