import type { Outcome, Severity, TrustLevel, ArtifactStatus } from "./types";

export const outcomeMeta: Record<Outcome, { label: string; cls: string; dot: string }> = {
  allow: { label: "Allow", cls: "text-allow bg-allow/10 border-allow/30", dot: "bg-allow" },
  allow_with_conditions: { label: "Allow with conditions", cls: "text-cond bg-cond/10 border-cond/30", dot: "bg-cond" },
  quarantine: { label: "Quarantine", cls: "text-quar bg-quar/10 border-quar/30", dot: "bg-quar" },
  block: { label: "Block", cls: "text-block bg-block/10 border-block/30", dot: "bg-block" },
};
export const sevMeta: Record<Severity, { cls: string; rank: number }> = {
  critical: { cls: "text-block bg-block/10 border-block/30", rank: 4 },
  high: { cls: "text-quar bg-quar/10 border-quar/30", rank: 3 },
  medium: { cls: "text-cond bg-cond/10 border-cond/30", rank: 2 },
  low: { cls: "text-accent bg-accent/10 border-accent/30", rank: 1 },
  info: { cls: "text-mute bg-raised border-line", rank: 0 },
};
export const trustOrder: TrustLevel[] = ["unknown", "origin_verified", "signed", "recorded"];
// Trust ladder as colour: unknown is the warning end, recorded the strongest.
export const trustColor: Record<TrustLevel, string> = {
  unknown: "var(--block)", origin_verified: "var(--quar)", signed: "var(--accent)",
  recorded: "var(--allow)",
};
export const statusLabel: Record<ArtifactStatus, string> = {
  submitted: "Submitted", quarantined: "Quarantined", admitted: "Admitted",
  admitted_with_conditions: "Admitted, conditions", blocked: "Blocked", revoked: "Revoked",
};
export const statusOutcome: Record<ArtifactStatus, Outcome | null> = {
  submitted: null, quarantined: "quarantine", admitted: "allow",
  admitted_with_conditions: "allow_with_conditions", blocked: "block", revoked: "block",
};
/** What to call an artifact's state: revoked beats its old decision; a block that came from a monitor alert says so. */
export type VerdictKey = Outcome | "revoked" | "block_monitor";
export const verdictKey = (status: ArtifactStatus, outcome: Outcome | null | undefined, id: string, monitorIds: Set<string>): VerdictKey | null => {
  if (status === "revoked") return "revoked";
  const o = outcome ?? statusOutcome[status];
  return o === "block" && monitorIds.has(id) ? "block_monitor" : o;
};
export const extraMeta: Record<"revoked" | "block_monitor", { label: string; cls: string; dot: string }> = {
  revoked: { label: "Revoked", cls: "text-block bg-block/10 border-block/40 border-dashed", dot: "bg-block" },
  block_monitor: { label: "Blocked (monitor)", cls: "text-block bg-block/10 border-block/30", dot: "bg-block" },
};
export const shortId = (id: string) => id.replace(/^lp:/, "").slice(0, 10);
export const ago = (iso: string) => {
  const s = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
  if (s < 90) return "just now";
  if (s < 5400) return `${Math.round(s / 60)} min ago`;
  if (s < 129600) return `${Math.round(s / 3600)} h ago`;
  return new Date(iso).toLocaleDateString(undefined, { month: "short", day: "numeric", year: "numeric" });
};
export const dt = (iso: string) => new Date(iso).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
export const riskColor = (n: number) => (n <= 30 ? "var(--allow)" : n <= 70 ? "var(--quar)" : "var(--block)");
