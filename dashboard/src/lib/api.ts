import { auth } from "./auth";
import type {
  Artifact, ArtifactDetail, Decision, Graph, MerkleLog, MonitorTick, PolicySignature, PolicyState,
  RevokeResult, StageEvent,
} from "./types";

const BASE = "/api";

async function req<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(BASE + path, {
    ...init,
    headers: { ...(init?.body instanceof FormData ? {} : { "Content-Type": "application/json" }), ...(auth.token() ? { Authorization: `Bearer ${auth.token()}` } : {}), ...(init?.headers ?? {}) },
  });
  if (res.status === 401) auth.setToken(null);
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}: ${(await res.text()).slice(0, 200)}`);
  return res.json() as Promise<T>;
}

export const api = {
  artifacts: () => req<Artifact[]>("/artifacts"),
  artifact: (id: string) => req<ArtifactDetail>(`/artifacts/${encodeURIComponent(id)}`),
  graph: (id: string, direction: "up" | "down") =>
    req<Graph>(`/graph/${encodeURIComponent(id)}?direction=${direction}`),
  revoke: (id: string, reason: string) =>
    req<RevokeResult>(`/revoke/${encodeURIComponent(id)}?reason=${encodeURIComponent(reason)}`, { method: "POST" }),
  verifyPassport: (id: string) => req<{ valid: boolean; problems: string[]; revoked: boolean }>(`/passports/${encodeURIComponent(id)}/verify`),
  whoami: () => req<import("./auth").Me>("/whoami"),
  upload: (file: File) => { const f = new FormData(); f.append("file", file); return req<{ upload_id: string; filename: string; size: number }>("/uploads", { method: "POST", body: f }); },
  approve: (id: string, body: { reason: string; expires: string }) =>
    req<Decision>(`/decisions/${encodeURIComponent(id)}/approve`, { method: "POST", body: JSON.stringify(body) }),
  policy: () => req<PolicyState>("/policy"),
  putPolicy: (policy: object, signatures: PolicySignature[], expires_at: string | null) =>
    req<PolicyState>("/policy", { method: "PUT", body: JSON.stringify({ policy, signatures, expires_at }) }),
  trustedPublishers: () => req<{ publishers: { name: string; key_id: string; scope: string[]; revoked: boolean }[]; revoked_keys: string[]; bootstrap_keys: string[] }>("/trusted-publishers"),
  flClients: () => req<{ client_id: string; trust: number; flagged_rounds: number; clean_rounds: number; quarantined: boolean; reasons: string[] }[]>("/fl/clients"),
  flRounds: () => req<string[]>("/fl/rounds"),
  flRound: (id: string) => req<{ round_id: string; mode: string; aggregator: string; scores: Record<string, Record<string, number>>; z: Record<string, Record<string, number>>; flagged: Record<string, string[]>; excluded: string[]; notes: string[] }>(`/fl/rounds/${encodeURIComponent(id)}`),
  monitorStatus: () => req<{ last: string | null; next: string | null; interval_minutes: number }>("/monitor/status"),
  log: () => req<MerkleLog>("/log"),
  latestTick: () => req<MonitorTick | null>("/monitor/latest"),
  tick: () => req<MonitorTick>("/monitor/tick", { method: "POST" }),
  startIntake: (body: { artifact_type: string; source: string; environment: string; claimed_origin?: string; claims?: Record<string, string> }) =>
    req<{ job_id: string; events_url: string }>("/intake", { method: "POST", body: JSON.stringify(body) }),
};

/** Subscribe to a job's SSE stream. Returns a close function. */
export function streamJob(
  eventsUrl: string,
  onEvent: (e: StageEvent) => void,
  onDone: (err?: string) => void,
): () => void {
  const es = new EventSource(BASE + eventsUrl + (eventsUrl.includes("?") ? "&" : "?") + `token=${encodeURIComponent(auth.token() ?? "")}`);
  let finished = false;
  es.onmessage = (m) => {
    const ev = JSON.parse(m.data) as StageEvent;
    onEvent(ev);
    if (ev.stage === "S7" && ev.status !== "started") { finished = true; es.close(); onDone(); }
  };
  es.onerror = () => {
    // The server closes the stream after the last event; that also fires onerror.
    es.close();
    if (!finished) onDone();
  };
  return () => es.close();
}
