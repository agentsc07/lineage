import { useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { api, streamJob } from "../lib/api";
import { session } from "../lib/session";
import type { ArtifactType, Decision, Fact, Finding, StageEvent, StageId } from "../lib/types";
import { Header, Risk, Severity_, Trust, Verdict } from "../components/ui";

const columns: { title: string; hint: string; stages: { id: StageId; name: string }[] }[] = [
  { title: "Prove", hint: "Where the bytes came from, and is it intact", stages: [{ id: "S0", name: "Acquire" }, { id: "S1", name: "Identify" }, { id: "S2", name: "Provenance" }] },
  { title: "Inspect", hint: "What it contains", stages: [{ id: "S3", name: "Static inspection" }, { id: "S4", name: "Deep inspection" }] },
  { title: "Review", hint: "What it intends to do", stages: [{ id: "S5", name: "LLM review" }] },
  { title: "Decide", hint: "Policy verdict and passport", stages: [{ id: "S6", name: "Decide" }, { id: "S7", name: "Admit" }] },
];
const presets: { label: string; type: ArtifactType; source: string; origin?: string; env: string }[] = [
  { label: "Hub model, fetched", type: "model", source: "hf:org/small-model", env: "prod" },
  { label: "Hub dataset, fetched", type: "dataset", source: "hf-dataset:org/notes", env: "prod" },
  { label: "PyPI package", type: "package", source: "pypi:requests==2.32.3", env: "prod" },
];
const provColour: Record<Fact["provenance"], string> = {
  computed: "text-allow", fetched: "text-allow", signed: "text-accent", declared: "text-quar",
};
type Stage = { status: "pending" | "running" | "done" | "failed" | "skipped"; message: string; findings: Finding[] };

export default function Intake() {
  const [type, setType] = useState<ArtifactType>("model");
  const [mode, setMode] = useState<"file" | "source">("source");
  const [source, setSource] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [origin, setOrigin] = useState("");
  const [claims, setClaims] = useState<Record<string, string>>({});
  const [facts, setFacts] = useState<Fact[]>([]);
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
    if (e.decision) { setDecision(e.decision); session.add({ ref: source || file?.name || "upload", artifact_type: type, decision: e.decision }); api.artifact(e.decision.artifact_id).then((d) => setFacts(d.passport?.passport.predicate.facts ?? [])).catch(() => {}); }
  };

  const submit = async (ev?: React.FormEvent) => {
    ev?.preventDefault();
    if ((mode === "source" ? !source.trim() : !file) || running) return;
    close.current(); clearInterval(timer.current);
    setStages({}); setFacts([]); setDecision(null); setErr(null); setRunning(true); queue.current = [];
    try {
      const used = Object.fromEntries(Object.entries(claims).filter(([, v]) => v.trim()));
      let src = source.trim();
      if (mode === "file") { const up = await api.upload(file!); src = `upload:${up.upload_id}`; }
      const job = await api.startIntake({ artifact_type: type, source: src, environment: env,
        ...(mode === "file" && origin.trim() ? { claimed_origin: origin.trim() } : {}), ...(Object.keys(used).length ? { claims: used } : {}) });
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
        <div className="flex gap-2 mb-3" role="tablist" aria-label="Where the bytes come from">
          {(["source", "file"] as const).map((m) => <button type="button" key={m} role="tab" aria-selected={mode === m} className={`btn ${mode === m ? "btn-primary" : ""}`} onClick={() => setMode(m)}>{m === "source" ? "Fetch from a hub" : "Upload a file"}</button>)}
        </div>
        <div className="grid sm:grid-cols-[130px_1fr_130px_auto] gap-3 items-end">
          <label className="text-sm text-mute">Type
            <select className="input mt-1" value={type} onChange={(e) => setType(e.target.value as ArtifactType)}>
              {["dataset", "model", "package", "tool", "agent"].map((t) => <option key={t}>{t}</option>)}</select></label>
          {mode === "source" ? (
            <label className="text-sm text-mute">Source
              <input className="input mt-1 font-mono" placeholder="hf:org/name@rev · hf-dataset:org/name · pypi:name==1.0" value={source} onChange={(e) => setSource(e.target.value)} /></label>
          ) : (
            <label className="text-sm text-mute">File or archive (.zip, .tar.gz, .whl)
              <input type="file" className="input mt-1" onChange={(e) => setFile(e.target.files?.[0] ?? null)} /></label>)}
          <label className="text-sm text-mute">Environment
            <select className="input mt-1" value={env} onChange={(e) => setEnv(e.target.value)}>{["dev", "staging", "prod"].map((t) => <option key={t}>{t}</option>)}</select></label>
          <button className="btn btn-primary" disabled={(mode === "source" ? !source.trim() : !file) || running}>{running ? "Running…" : "Start intake"}</button>
        </div>
        {mode === "file" && (
          <label className="text-sm text-mute block mt-3">Claimed origin (optional)
            <input className="input mt-1 font-mono" placeholder="hf:meta-llama/Llama-3.2-1B@<commit sha>: every file is compared with what that repo published" value={origin} onChange={(e) => setOrigin(e.target.value)} />
            <span className="text-xs text-faint">No claim means trust stays <span className="mono">unknown</span>. Hints found inside the upload are shown but never trusted.</span></label>)}
        <details className="mt-3">
          <summary className="text-sm text-mute cursor-pointer">Claims about this artifact (all recorded as <span className="mono">declared</span>, never used to clear a check)</summary>
          <div className="grid sm:grid-cols-5 gap-3 mt-2">
            {["publisher", "licence", "base_model", "released_at", "description"].map((k) => (
              <label key={k} className="text-xs text-mute">{k}<input className="input mt-1" value={claims[k] ?? ""} onChange={(e) => setClaims((c) => ({ ...c, [k]: e.target.value }))} /></label>))}
          </div>
        </details>
        <div className="flex flex-wrap gap-2 mt-3 items-center">
          <span className="text-xs text-faint">Try:</span>
          {presets.map((p) => <button type="button" key={p.label} className="text-xs border border-line rounded-full px-2.5 py-1 text-mute hover:text-ink hover:border-faint" onClick={() => { setMode("source"); setType(p.type); setSource(p.source); setEnv(p.env); }}>{p.label}</button>)}
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
                    <div key={f.id + f.title} className={`mt-2 ml-[22px] text-xs border rounded-md p-2 ${f.id.startsWith("CHECK.NOT_RUN.") ? "border-quar/60 bg-quar/10" : "border-line bg-bg"}`}>
                      <div className="flex items-center gap-2 mb-1"><Severity_ s={f.severity} /><span className="mono text-faint truncate">{f.id}</span>{f.id.startsWith("CHECK.NOT_RUN.") && <span className="text-quar font-medium">did not run</span>}</div>
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

      {facts.length > 0 && (
        <section className="card mt-6">
          <div className="card-h"><h2 className="h-title">Facts <span className="text-faint font-normal">({facts.length})</span></h2>
            <p className="text-xs text-faint">Only computed, fetched and signed facts can relax a check; declared facts only add risk.</p></div>
          <table className="w-full text-sm"><thead><tr className="text-left text-xs text-faint"><th className="p-3">Fact</th><th>Value</th><th>Class</th><th>Source</th></tr></thead>
            <tbody>{facts.map((f, i) => (
              <tr key={i} className="border-t border-line/60 align-top"><td className="p-3 mono">{f.key}</td>
                <td className="pr-3 break-all max-w-[360px]">{(f.value ?? "").slice(0, 120)}</td>
                <td className={`pr-3 font-medium ${provColour[f.provenance]}`}>{f.provenance}</td>
                <td className="pr-3 text-mute text-xs">{f.source}</td></tr>))}</tbody></table>
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
