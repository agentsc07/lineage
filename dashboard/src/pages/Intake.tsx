import { useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { api, streamJob } from "../lib/api";
import { session } from "../lib/session";
import type { ArtifactType, Decision, Finding, StageEvent, StageId } from "../lib/types";
import { Header, Risk, Severity_, Trust, Verdict } from "../components/ui";

const columns: { title: string; hint: string; stages: { id: StageId; name: string }[] }[] = [
  { title: "Prove", hint: "Who made it, and is it intact", stages: [{ id: "S1", name: "Identify" }, { id: "S2", name: "Provenance" }] },
  { title: "Inspect", hint: "What it contains", stages: [{ id: "S3", name: "Static inspection" }, { id: "S4", name: "Deep inspection" }] },
  { title: "Review", hint: "What it intends to do", stages: [{ id: "S5", name: "LLM review" }] },
  { title: "Decide", hint: "Policy verdict and passport", stages: [{ id: "S6", name: "Decide" }, { id: "S7", name: "Admit" }] },
];
const presets: { label: string; type: ArtifactType; ref: string; env: string }[] = [
  { label: "Signed dataset", type: "dataset", ref: "apollo/radiology-notes@1.0.0", env: "prod" },
  { label: "Unknown hub model", type: "model", ref: "shady-org/llama-3.2-1b-medical-ft", env: "prod" },
  { label: "LiteLLM-style package", type: "package", ref: "litellm==1.82.7", env: "prod" },
  { label: "MCP tool", type: "tool", ref: "mcp://apollo/dicom-fetch", env: "dev" },
];
type Stage = { status: "pending" | "running" | "done" | "failed" | "skipped"; message: string; findings: Finding[] };

export default function Intake() {
  const [type, setType] = useState<ArtifactType>("model");
  const [ref, setRef] = useState("");
  const [env, setEnv] = useState("prod");
  const [stages, setStages] = useState<Record<string, Stage>>({});
  const [decision, setDecision] = useState<Decision | null>(null);
  const [running, setRunning] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const close = useRef<() => void>(() => {});
  const queue = useRef<StageEvent[]>([]);
  const timer = useRef<number>();
  const done = useRef(false);

  useEffect(() => () => { close.current(); clearInterval(timer.current); }, []);

  const apply = (e: StageEvent) => {
    setStages((s) => ({ ...s, [e.stage]: {
      status: e.status === "started" ? "running" : e.status === "completed" ? "done" : e.status,
      message: e.message || s[e.stage]?.message || "",
      findings: e.findings.length ? e.findings : s[e.stage]?.findings ?? [] } }));
    if (e.decision) { setDecision(e.decision); session.add({ ref, artifact_type: type, decision: e.decision }); }
  };

  const submit = async (ev?: React.FormEvent) => {
    ev?.preventDefault();
    if (!ref.trim() || running) return;
    close.current(); clearInterval(timer.current);
    setStages({}); setDecision(null); setErr(null); setRunning(true); queue.current = [];
    try {
      const job = await api.startIntake({ artifact_type: type, ref: ref.trim(), environment: env });
      // Events can arrive in a burst; replay them at a readable pace.
      timer.current = window.setInterval(() => {
        const next = queue.current.shift();
        if (next) apply(next);
        else if (done.current) { clearInterval(timer.current); setRunning(false); }
      }, 380);
      done.current = false;
      close.current = streamJob(job.events_url, (e) => queue.current.push(e), () => { done.current = true; });
    } catch (e: any) { setErr(e.message); setRunning(false); }
  };

  const all = Object.values(stages).flatMap((s) => s.findings);
  return (
    <div className="page">
      <Header title="Intake" sub="Submit an artifact and watch it go through each stage before a verdict is issued." />
      <form onSubmit={submit} className="card p-4 mb-6">
        <div className="grid sm:grid-cols-[130px_1fr_130px_auto] gap-3 items-end">
          <label className="text-sm text-mute">Type
            <select className="input mt-1" value={type} onChange={(e) => setType(e.target.value as ArtifactType)}>
              {["dataset", "model", "package", "tool", "agent"].map((t) => <option key={t}>{t}</option>)}</select></label>
          <label className="text-sm text-mute">Reference
            <input className="input mt-1 font-mono" placeholder="Path, hub id, or pkg==1.2.3" value={ref} onChange={(e) => setRef(e.target.value)} /></label>
          <label className="text-sm text-mute">Environment
            <select className="input mt-1" value={env} onChange={(e) => setEnv(e.target.value)}>{["dev", "staging", "prod"].map((t) => <option key={t}>{t}</option>)}</select></label>
          <button className="btn btn-primary" disabled={!ref.trim() || running}>{running ? "Running…" : "Start intake"}</button>
        </div>
        <div className="flex flex-wrap gap-2 mt-3 items-center">
          <span className="text-xs text-faint">Try:</span>
          {presets.map((p) => <button type="button" key={p.label} className="text-xs border border-line rounded-full px-2.5 py-1 text-mute hover:text-ink hover:border-faint" onClick={() => { setType(p.type); setRef(p.ref); setEnv(p.env); }}>{p.label}</button>)}
        </div>
        {err && <p className="text-sm text-block mt-3">{err}</p>}
      </form>

      <div className="grid md:grid-cols-2 xl:grid-cols-4 gap-4 items-start">
        {columns.map((c) => (
          <section key={c.title} className="card">
            <div className="card-h flex-col !items-start !gap-0"><h2 className="h-title">{c.title}</h2><p className="text-xs text-faint">{c.hint}</p></div>
            <ul>{c.stages.map((st) => {
              const s = stages[st.id]; const status = s?.status ?? "pending";
              return (
                <li key={st.id} className="p-4 border-b border-line/60 last:border-0">
                  <div className="flex items-center gap-2.5">
                    <StageDot status={status} />
                    <span className={`text-sm font-medium ${status === "pending" ? "text-faint" : ""}`}>{st.name}</span>
                    <span className="mono text-faint ml-auto">{st.id}</span>
                  </div>
                  {s?.message && status !== "pending" && <p className="text-xs text-mute mt-1.5 ml-[22px]">{s.message}</p>}
                  {s?.findings.map((f) => (
                    <div key={f.id} className="mt-2 ml-[22px] text-xs border border-line rounded-md p-2 bg-bg">
                      <div className="flex items-center gap-2 mb-1"><Severity_ s={f.severity} /><span className="mono text-faint truncate">{f.id}</span></div>
                      <p>{f.title}</p>
                      {f.evidence[0] && <p className="mono text-mute mt-1 break-all">{f.evidence[0].ref}</p>}
                    </div>))}
                </li>);
            })}</ul>
          </section>))}
      </div>

      {decision && (
        <section className="card mt-6 p-5 flex flex-wrap gap-6 items-start" aria-live="polite">
          <div className="min-w-[200px]">
            <p className="text-sm text-mute mb-2">Verdict for {env}</p>
            <Verdict outcome={decision.outcome} size="lg" />
            <div className="mt-4 flex flex-col gap-2 text-sm"><Trust level={decision.trust_level} /><Risk score={decision.risk_score} /></div>
          </div>
          <div className="flex-1 min-w-[240px]">
            <p className="text-sm text-mute mb-2">Why</p>
            <ul className="text-sm list-disc pl-4 space-y-1">{decision.reasons.map((r, i) => <li key={i}>{r}</li>)}</ul>
            {decision.conditions.length > 0 && <p className="text-sm text-cond mt-2">Conditions: {decision.conditions.join("; ")}</p>}
            <p className="text-xs text-faint mt-3">{all.length} finding{all.length === 1 ? "" : "s"} · policy <span className="mono">{decision.policy_version}</span></p>
          </div>
          <div className="flex gap-2">
            <Link className="btn" to={`/artifacts/${encodeURIComponent(decision.artifact_id)}`}>Open artifact</Link>
            {decision.outcome === "quarantine" && <Link className="btn btn-primary" to="/approvals">Review in approvals</Link>}
          </div>
        </section>)}
    </div>
  );
}

function StageDot({ status }: { status: Stage["status"] }) {
  const base = "w-3.5 h-3.5 rounded-full border-2 shrink-0";
  if (status === "done") return <span className={`${base} bg-allow border-allow`} aria-label="done" />;
  if (status === "running") return <span className={`${base} border-accent border-t-transparent animate-spin`} aria-label="running" />;
  if (status === "failed") return <span className={`${base} bg-block border-block`} aria-label="failed" />;
  if (status === "skipped") return <span className={`${base} border-faint border-dashed`} aria-label="skipped" />;
  return <span className={`${base} border-line`} aria-label="waiting" />;
}
