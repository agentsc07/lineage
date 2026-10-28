import { useCallback, useEffect, useRef, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { api, describeError, streamJob } from "../lib/api";
import { auth } from "../lib/auth";
import { session } from "../lib/session";
import type { ArtifactType, ArtifactView, Decision, Finding, Limits, StageEvent } from "../lib/types";
import { Header } from "../components/ui";
import { reduce, STAGES, type StageState } from "./intake/model";
import { DecisionPanel, IdentityPanel, PassportPanel, StageRow } from "./intake/panels";

const columns: { title: string; hint: string; ids: string[] }[] = [
  { title: "Prove", hint: "Where the bytes came from, and is it intact", ids: ["S0", "S1", "S2"] },
  { title: "Inspect", hint: "What it contains", ids: ["S3", "S4"] },
  { title: "Review", hint: "What it intends to do", ids: ["S5"] },
  { title: "Decide", hint: "Policy verdict and record", ids: ["S6", "S7"] },
];
const presets: { label: string; type: ArtifactType; source: string; env: string }[] = [
  { label: "Hub model, fetched", type: "model", source: "hf:org/small-model", env: "prod" },
  { label: "Hub dataset, fetched", type: "dataset", source: "hf-dataset:org/notes", env: "prod" },
  { label: "PyPI package", type: "package", source: "pypi:requests==2.32.3", env: "prod" },
];
interface Sample { label: string; file: string; type: ArtifactType; env: string; claimed_origin?: string; expect: string }

const CLAIM_FIELDS = [
  { key: "name", label: "Name (uploads)", placeholder: "triage-ft", help: "What the catalogue calls it. Without it, the file or folder name is used. Hub sources are named by the hub." },
  { key: "version", label: "Version (uploads)", placeholder: "0.2.0", help: "Your own version label. Without it an upload is 0.0.0. Hub sources use the commit (hf:) or the release (pypi:)." },
  { key: "publisher", label: "Publisher", placeholder: "nvidia", help: "A name. Checked against the publisher allow and block lists and for look-alikes. A name you type is never treated as verified." },
  { key: "base_model", label: "Base model (Hugging Face repo id)", placeholder: "nvidia/Llama-3.1-Nemotron-Nano-4B-v1.1", help: "The repository id of the model this was fine-tuned from. Lineage fetches that repo's weights header and compares embeddings; a mismatch raises risk. It is not a passport id." },
  { key: "licence", label: "Licence", placeholder: "apache-2.0", help: "Compared with the policy's allowed licences. A declared licence is never counted as allowed." },
  { key: "released_at", label: "Released at (date)", placeholder: "2026-10-01", help: "Shown only. The release-age cooldown ignores a date you type; it needs one from the hub or a signed passport." },
  { key: "description", label: "What it is for", placeholder: "Helper for calling LLM providers", help: "Used as the stated purpose when the AI reviewer judges whether code behaviour fits." },
];

export default function Intake() {
  const { jobId } = useParams();
  const navigate = useNavigate();
  const [type, setType] = useState<ArtifactType>("model");
  const [mode, setMode] = useState<"file" | "source">("source");
  const [source, setSource] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [origin, setOrigin] = useState("");
  const [claims, setClaims] = useState<Record<string, string>>({});
  const [env, setEnv] = useState("prod");
  const [stages, setStages] = useState<Record<string, StageState>>({});
  const [decision, setDecision] = useState<Decision | null>(null);
  const [view, setView] = useState<ArtifactView | null>(null);
  const [running, setRunning] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [label, setLabel] = useState("");
  const [limits, setLimits] = useState<Limits | null>(null);
  const [samples, setSamples] = useState<Sample[]>([]);
  const close = useRef<() => void>(() => {});
  const queue = useRef<StageEvent[]>([]);
  const timer = useRef<number>();
  const done = useRef(false);
  const started = useRef<string | null>(null); // the job this page started itself (so the URL change does not trigger a recovery)

  useEffect(() => () => { close.current(); clearInterval(timer.current); }, []);
  useEffect(() => { api.limits().then(setLimits).catch(() => {}); fetch("/samples/manifest.json").then((r) => (r.ok ? r.json() : [])).then(setSamples).catch(() => {}); }, []);

  const refreshView = useCallback((id: string) => api.artifactView(id).then((v) => { setView(v); if (v.decision) setDecision(v.decision); }).catch((e) => setErr(describeError(e))), []);

  const apply = useCallback((e: StageEvent) => {
    setStages((s) => reduce(s, e));
    if (e.status === "failed") setErr(`Stage ${e.stage} ${e.name} failed: ${e.message}`);
    if (e.decision) { setDecision(e.decision); session.add({ ref: label || e.decision.artifact_id, artifact_type: type, decision: e.decision, by: auth.me()?.name }); }
  }, [label, type]);

  const follow = useCallback((eventsUrl: string, paced: boolean) => {
    close.current(); clearInterval(timer.current);
    queue.current = []; done.current = false; setRunning(true);
    const finishUp = () => {
      clearInterval(timer.current); setRunning(false);
      const last = queue.current;
      void last;
    };
    if (paced) {
      timer.current = window.setInterval(() => {
        const next = queue.current.shift();
        if (next) apply(next);
        else if (done.current) { finishUp(); }
      }, 380);
    }
    close.current = streamJob(eventsUrl, (e) => { if (paced) queue.current.push(e); else apply(e); }, (err) => { if (err) setErr(`Could not open the event stream: ${err}`); done.current = true; if (!paced) finishUp(); });
  }, [apply]);

  // After the stream ends, load what the server recorded (identity, classes, attestation, next action).
  useEffect(() => { if (!running && decision && (!view || view.artifact_id !== decision.artifact_id)) refreshView(decision.artifact_id); }, [running, decision, view, refreshView]);

  // Reload recovery: /intake/<job_id> rebuilds the page from the persisted job, its events and its decision.
  useEffect(() => {
    if (!jobId || started.current === jobId) return;
    setStages({}); setDecision(null); setView(null); setErr(null);
    api.job(jobId).then((j) => { setEnv(j.environment ?? "prod"); if (j.artifact_type) setType(j.artifact_type as ArtifactType); setLabel(j.label ?? ""); follow(`/events/${jobId}`, false); })
      .catch((e) => setErr(describeError(e)));
  }, [jobId, follow]);

  const submit = async (o?: { file?: File; type?: ArtifactType; env?: string; origin?: string; source?: string }) => {
    const f = o?.file ?? (mode === "file" ? file : null);
    const src = o?.source ?? (mode === "source" ? source.trim() : "");
    const t = o?.type ?? type, e = o?.env ?? env, org = o?.origin ?? origin.trim();
    if ((!f && !src) || running) return;
    setStages({}); setDecision(null); setView(null); setErr(null); setRunning(true);
    try {
      if (f && limits && f.size > limits.max_upload_mb * 1024 * 1024) throw new Error(`File too large: ${(f.size / 1048576).toFixed(1)} MB; this server accepts up to ${limits.max_upload_mb} MB (LINEAGE_MAX_UPLOAD_MB).`);
      const used = Object.fromEntries(Object.entries(claims).filter(([, v]) => v.trim()));
      let source_ = src;
      if (f) { const up = await api.upload(f); source_ = `upload:${up.upload_id}`; }
      setLabel(f?.name ?? src);
      const job = await api.startIntake({ artifact_type: t, source: source_, environment: e, ...(f && org ? { claimed_origin: org } : {}), ...(Object.keys(used).length ? { claims: used } : {}) });
      started.current = job.job_id;
      navigate(`/intake/${job.job_id}`);
      follow(job.events_url, true);
    } catch (x) { setErr(describeError(x)); setRunning(false); }
  };

  const loadSample = async (s: Sample) => {
    try {
      const r = await fetch(`/samples/${encodeURIComponent(s.file)}`);
      if (!r.ok) throw new Error(`sample ${s.file} is not available`);
      const f = new File([await r.blob()], s.file);
      setMode("file"); setFile(f); setType(s.type); setEnv(s.env); setOrigin(s.claimed_origin ?? "");
      await submit({ file: f, type: s.type, env: s.env, origin: s.claimed_origin ?? "" });
    } catch (x) { setErr(describeError(x)); }
  };

  const all: Finding[] = Object.values(stages).flatMap((s) => s.findings);
  const state = (id: string) => stages[id];
  return (
    <div className="page">
      <Header title="Intake" sub="Submit an artifact and watch it go through each stage before a verdict is issued." />
      <form onSubmit={(ev) => { ev.preventDefault(); submit(); }} className="card p-4 mb-6">
        <div className="flex gap-2 mb-3 items-center flex-wrap" role="tablist" aria-label="Where the bytes come from">
          {(["source", "file"] as const).map((m) => <button type="button" key={m} role="tab" aria-selected={mode === m} className={`btn ${mode === m ? "btn-primary" : ""}`} onClick={() => setMode(m)}>{m === "source" ? "From a hub" : "Upload a file"}</button>)}
          {samples.length > 0 && (
            <select className="input !w-auto ml-auto" aria-label="Load sample" value="" onChange={(e) => { const s = samples.find((x) => x.file === e.target.value); if (s) loadSample(s); }}>
              <option value="">Load sample…</option>
              {samples.map((s) => <option key={s.file} value={s.file}>{s.label}</option>)}
            </select>)}
        </div>
        <div className="grid sm:grid-cols-[130px_1fr_130px_auto] gap-3 items-end">
          <label className="text-sm text-mute">Type
            <select className="input mt-1" value={type} onChange={(e) => setType(e.target.value as ArtifactType)}>
              {["dataset", "model", "package", "tool", "agent"].map((t) => <option key={t}>{t}</option>)}</select></label>
          {mode === "source" ? (
            <label className="text-sm text-mute">Source
              <input className="input mt-1 font-mono" placeholder="hf:org/name@rev · hf-dataset:org/name · pypi:name==1.0" value={source} onChange={(e) => setSource(e.target.value)} /></label>
          ) : (
            <label className="text-sm text-mute">File or archive (.zip, .tar.gz, .whl){limits ? ` · up to ${limits.max_upload_mb} MB` : ""}
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
          <summary className="text-sm text-mute cursor-pointer">Optional: what you say about this artifact (recorded as <span className="mono">declared</span>; it can add risk but never earns trust)</summary>
          <div className="grid sm:grid-cols-2 gap-3 mt-2">
            {CLAIM_FIELDS.map((c) => (
              <label key={c.key} className="text-xs text-mute">{c.label}
                <input className="input mt-1" placeholder={c.placeholder} value={claims[c.key] ?? ""} onChange={(e) => setClaims((m) => ({ ...m, [c.key]: e.target.value }))} />
                <span className="text-faint block mt-0.5">{c.help}</span></label>))}
          </div>
          <p className="text-xs text-faint mt-2">Publisher keys are not entered here. A passport shipped with the artifact is verified against the keys your administrator lists under Trusted publishers; a key that arrives with an upload is never trusted.</p>
        </details>
        <div className="flex flex-wrap gap-2 mt-3 items-center">
          <span className="text-xs text-faint">Try:</span>
          {presets.map((p) => <button type="button" key={p.label} className="text-xs border border-line rounded-full px-2.5 py-1 text-mute hover:text-ink hover:border-faint" onClick={() => { setMode("source"); setType(p.type); setSource(p.source); setEnv(p.env); }}>{p.label}</button>)}
        </div>
        {err && <p className="text-sm text-block mt-3" role="alert" data-testid="intake-error">{err}</p>}
      </form>

      {(jobId || running || Object.keys(stages).length > 0) && label && <p className="text-sm text-mute mb-3">Job <span className="mono">{jobId}</span> · {label} · {env}</p>}
      <div className="grid md:grid-cols-2 xl:grid-cols-4 gap-4 items-start" data-testid="stages">
        {columns.map((c) => (
          <section key={c.title} className="card">
            <div className="card-h flex-col !items-start !gap-0"><h2 className="h-title">{c.title}</h2><p className="text-xs text-faint">{c.hint}</p></div>
            <ul>{c.ids.map((id) => { const st = STAGES.find((s) => s.id === id)!; return <StageRow key={id} id={id} name={st.name} what={st.what} state={state(id)} decision={decision} view={view} />; })}</ul>
          </section>))}
      </div>

      {decision && <DecisionPanel decision={decision} view={view} env={decision.environment || env} findings={all} onChanged={() => refreshView(decision.artifact_id)} />}
      {view && <IdentityPanel view={view} />}
      {view && decision && <PassportPanel view={view} decision={decision} env={decision.environment || env} />}
      {decision && <p className="mt-6 text-sm"><Link className="text-accent" to={`/artifacts/${encodeURIComponent(decision.artifact_id)}`}>Open the artifact page</Link>{decision.outcome === "quarantine" && <> · <Link className="text-accent" to="/approvals">Approvals queue</Link></>} · <Link className="text-accent" to={`/graph/${encodeURIComponent(decision.artifact_id)}`}>Lineage graph</Link></p>}
    </div>
  );
}
