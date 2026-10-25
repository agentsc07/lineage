import type {
  Artifact, ArtifactDetail, Decision, Graph, MerkleLog, MonitorTick, PolicySignature, PolicyState,
  RevokeResult, StageEvent,
} from "./types";

const BASE = "/api";

async function req<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(BASE + path, {
    ...init,
    headers: { "Content-Type": "application/json", ...(init?.headers ?? {}) },
  });
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
  approve: (id: string, body: { approver: string; reason: string; expires: string }) =>
    req<Decision>(`/decisions/${encodeURIComponent(id)}/approve`, { method: "POST", body: JSON.stringify(body) }),
  policy: () => req<PolicyState>("/policy"),
  putPolicy: (policy: object, signatures: PolicySignature[], expires_at: string | null) =>
    req<PolicyState>("/policy", { method: "PUT", body: JSON.stringify({ policy, signatures, expires_at }) }),
  log: () => req<MerkleLog>("/log"),
  tick: () => req<MonitorTick>("/monitor/tick", { method: "POST" }),
  startIntake: (body: { artifact_type: string; ref: string; environment: string }) =>
    req<{ job_id: string; events_url: string }>("/intake", { method: "POST", body: JSON.stringify(body) }),
};

/** Subscribe to a job's SSE stream. Returns a close function. */
export function streamJob(
  eventsUrl: string,
  onEvent: (e: StageEvent) => void,
  onDone: (err?: string) => void,
): () => void {
  const es = new EventSource(BASE + eventsUrl);
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
