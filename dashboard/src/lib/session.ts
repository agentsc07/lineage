// Decisions made in this browser session. The server is the source of truth for the catalogue; this
// store keeps intake results and approvals visible on Overview/Approvals before the server persists them.
import { useSyncExternalStore } from "react";
import type { Decision } from "./types";

export interface SessionDecision {
  ref: string; artifact_type: string; decision: Decision; approved?: { by: string; reason: string; expires: string };
}
const KEY = "lineage.session.decisions";
let state: SessionDecision[] = [];
try { state = JSON.parse(localStorage.getItem(KEY) ?? "[]"); } catch { state = []; }
const subs = new Set<() => void>();
const emit = () => { try { localStorage.setItem(KEY, JSON.stringify(state)); } catch { /* storage unavailable */ } subs.forEach((f) => f()); };

export const session = {
  add(d: SessionDecision) { state = [d, ...state].slice(0, 50); emit(); },
  approve(artifactId: string, a: SessionDecision["approved"], updated?: Decision) {
    state = state.map((s) => s.decision.artifact_id === artifactId && !s.approved
      ? { ...s, approved: a, decision: updated ?? s.decision } : s);
    emit();
  },
  clear() { state = []; emit(); },
};
export function useSession(): SessionDecision[] {
  return useSyncExternalStore((f) => { subs.add(f); return () => subs.delete(f); }, () => state);
}
