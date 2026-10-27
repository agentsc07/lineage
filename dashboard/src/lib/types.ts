// Hand-written mirror of lineage/schemas (frozen contracts). Keep in sync with docs/API.md.
export type ArtifactType = "dataset" | "model" | "package" | "tool" | "agent";
export type TrustLevel = "unknown" | "origin_verified" | "signed" | "recorded";
export type Severity = "info" | "low" | "medium" | "high" | "critical";
export type Outcome = "allow" | "allow_with_conditions" | "quarantine" | "block";
export type ArtifactStatus =
  | "submitted" | "quarantined" | "admitted" | "admitted_with_conditions" | "blocked" | "revoked" | "unregistered";
export type StageId = "S0" | "S1" | "S2" | "S3" | "S4" | "S5" | "S6" | "S7";

export interface Evidence { kind: string; ref: string; detail: string }
export interface Finding {
  id: string; title: string; severity: Severity; category: string; stage: StageId;
  evidence: Evidence[]; score: number; source: "deterministic" | "statistical" | "llm" | "human";
  grounded: boolean;
}
export interface Decision {
  artifact_id: string; environment: string; outcome: Outcome; reasons: string[]; primary_reason?: string; secondary_reasons?: string[];
  conditions: string[]; risk_score: number; trust_level: TrustLevel; findings: Finding[];
  policy_version: string; decided_at: string; approver?: string | null;
}
export interface Artifact {
  id: string; artifact_type: ArtifactType; name: string; version: string;
  trust_level: TrustLevel; risk_score: number; status: ArtifactStatus;
  environment: string; outcome?: Outcome | null; created_at: string;
}
export interface PassportBody {
  artifact_type: ArtifactType; name: string; version: string;
  source: { hub?: string | null; repo?: string | null; commit?: string | null; url?: string | null };
  contents: { merkle_root: string; files: Record<string, string> };
  parents: string[]; action?: { kind: string } | null; trust_level: TrustLevel;
  findings_digest: string; risk_score: number; certificates: string[];
  issued_by: { name: string; key_id?: string | null }; issued_at: string; expires_at?: string | null;
  facts?: Fact[];
}
export interface Fact { key: string; value: string | null; provenance: "computed" | "fetched" | "signed" | "declared"; source: string; at: string }
export interface SignedPassport {
  passport: { _type: string; subject: { name: string; digest: Record<string, string> }[]; predicateType: string; predicate: PassportBody };
  signature: string; key_id: string;
}
export interface ArtifactDetail {
  artifact: Artifact; passport: SignedPassport | null; findings: Finding[]; decision: Decision | null;
}
export interface StageEvent {
  job_id: string; stage: StageId; name: string; status: "started" | "completed" | "skipped" | "failed";
  findings: Finding[]; message: string; decision?: Decision | null; ts: string;
}
export interface GraphNode {
  id: string; label: string; artifact_type: ArtifactType; trust_level: TrustLevel;
  status: ArtifactStatus; risk_score: number;
}
export interface Graph { root: string; direction: "up" | "down"; nodes: GraphNode[]; edges: { source: string; target: string; kind: string }[] }
export interface RevokeResult { revoked: string; reason: string; blast_radius: GraphNode[] }
export interface PolicySignature { role: string; key_id: string; signature: string }
export interface PolicyState {
  policy: Record<string, any>; version: string; signatures: PolicySignature[];
  roles_required: number; roles_total: number; expires_at?: string | null;
}
export interface Alert { artifact_id: string; kind: string; severity: Severity; message: string; blast_radius: GraphNode[] }
export interface MonitorTick { checked: number; alerts: Alert[]; ts: string }
export interface LogEntry { index: number; entry_hash: string; kind: string; ref: string; ts: string }
export interface MerkleLog { size: number; root: string; entries: LogEntry[] }
