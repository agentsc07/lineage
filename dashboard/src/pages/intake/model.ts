import type { Decision, Finding, StageEvent, StageId } from "../../lib/types";

export type StageStatus = "pending" | "running" | "done" | "findings" | "not_run" | "failed" | "blocked";
export interface StageState { status: StageStatus; message: string; findings: Finding[]; elapsedMs?: number; startedAt?: string }

export const STAGES: { id: StageId; name: string; what: string }[] = [
  { id: "S0", name: "Acquire", what: "Get the bytes (upload, or fetched from the hub)" },
  { id: "S1", name: "Identify", what: "Hash every file, compute the Merkle root" },
  { id: "S2", name: "Provenance", what: "Origin, publisher, signature, licence, release age" },
  { id: "S3", name: "Static inspection", what: "Rules over the files" },
  { id: "S4", name: "Deep inspection", what: "Parent, weights, behaviour, taint, dataset statistics" },
  { id: "S5", name: "LLM review", what: "Model-assisted review; evidence is checked against the source" },
  { id: "S6", name: "Decide", what: "Policy verdict" },
  { id: "S7", name: "Admit", what: "Record, sign, admit or hold" },
];

export const isNotRun = (f: Finding) => f.id.startsWith("CHECK.NOT_RUN.");

/** The state a stage ends in, from the real finishing event only. */
export function finish(e: StageEvent, prev?: StageState): StageState {
  const findings = e.findings.length ? e.findings : prev?.findings ?? [];
  const real = findings.filter((f) => !isNotRun(f) && f.severity !== "info");
  const unrun = findings.filter(isNotRun);
  let status: StageStatus = "done";
  if (e.status === "failed") status = "failed";
  else if (e.status === "skipped") status = "not_run";
  else if (e.decision?.outcome === "block") status = "blocked";
  else if (e.stage === "S7" && /blocked$/.test(e.message)) status = "blocked";
  else if (real.length) status = "findings";
  else if (unrun.length && !findings.some((f) => !isNotRun(f))) status = "not_run";
  return { status, message: e.message || prev?.message || "", findings, elapsedMs: e.elapsed_ms ?? undefined, startedAt: prev?.startedAt };
}

export function reduce(state: Record<string, StageState>, e: StageEvent): Record<string, StageState> {
  const prev = state[e.stage];
  if (e.status === "started") return { ...state, [e.stage]: { status: "running", message: "", findings: [], startedAt: e.ts } };
  return { ...state, [e.stage]: finish(e, prev) };
}

/** What an unrun check cost under this policy: the priced finding in the decision (its score), not an estimate. */
export function unrunCost(f: Finding, decision: Decision | null): { severity: string; points: number } | null {
  const priced = decision?.findings.find((d) => d.id === f.id);
  return priced ? { severity: priced.severity, points: priced.score } : null;
}

export const LABEL: Record<StageStatus, string> = {
  pending: "pending", running: "running", done: "done", findings: "findings", not_run: "did not run", failed: "failed", blocked: "blocked",
};
