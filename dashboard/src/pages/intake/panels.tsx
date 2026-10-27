import { useEffect, useState } from "react";
import { api, describeError } from "../../lib/api";
import { auth } from "../../lib/auth";
import { dt } from "../../lib/format";
import type { ArtifactView, AttestationView, Decision, Fact, Finding, OriginStatus, SignedPassport } from "../../lib/types";
import { Reasons, Risk, Severity_, Trust, Verdict } from "../../components/ui";
import { isNotRun, LABEL, unrunCost, type StageState, type StageStatus } from "./model";

const provColour: Record<Fact["provenance"], string> = { computed: "text-allow", fetched: "text-allow", signed: "text-accent", declared: "text-quar" };
const originColour: Record<OriginStatus, string> = { matching: "text-allow", changed: "text-block", missing: "text-block", extra: "text-quar", unchecked: "text-faint" };
const classLabel = { hard_block: "hard block: no approval can change it", policy_dependent: "policy-dependent: an approval can accept it", scored: "adds risk points only" } as const;
const classColour = { hard_block: "text-block border-block/40", policy_dependent: "text-quar border-quar/40", scored: "text-mute border-line" } as const;

/** Text with any full `lp:` id shortened; clicking a short id copies the whole one. */
export function WithIds({ text }: { text: string }) {
  const [copied, setCopied] = useState<string | null>(null);
  const parts = text.split(/(lp:[0-9a-f]{64})/);
  return <>{parts.map((p, i) => /^lp:[0-9a-f]{64}$/.test(p)
    ? <button key={i} type="button" className="mono underline decoration-dotted text-accent" title={`${p} (click to copy)`}
        onClick={() => { navigator.clipboard?.writeText(p).then(() => { setCopied(p); setTimeout(() => setCopied(null), 1500); }).catch(() => {}); }}>{copied === p ? "copied" : `${p.slice(0, 11)}…${p.slice(-6)}`}</button>
    : <span key={i}>{p}</span>)}</>;
}

export function StageDot({ status }: { status: StageStatus }) {
  if (status === "not_run") return (  // a hollow circle with a slash: static, so it cannot be mistaken for a spinner
    <svg className="w-3.5 h-3.5 shrink-0 text-quar" viewBox="0 0 14 14" aria-label={LABEL[status]} role="img"><circle cx="7" cy="7" r="5.5" fill="none" stroke="currentColor" strokeWidth="1.6" /><line x1="3.4" y1="10.6" x2="10.6" y2="3.4" stroke="currentColor" strokeWidth="1.6" /></svg>);
  const base = "w-3.5 h-3.5 rounded-full border-2 shrink-0";
  const cls: Record<StageStatus, string> = {
    pending: "border-line", running: "border-accent border-t-transparent animate-spin", done: "bg-allow border-allow", findings: "bg-quar border-quar",
    not_run: "", failed: "bg-block border-block", blocked: "bg-block border-block",
  };
  return <span className={`${base} ${cls[status]}`} aria-label={LABEL[status]} />;
}

export function StageRow({ id, name, what, state, decision, view }: { id: string; name: string; what: string; state?: StageState; decision: Decision | null; view: ArtifactView | null }) {
  const status = state?.status ?? "pending";
  const unrun = state?.findings.filter(isNotRun) ?? [];
  const shown = state?.findings.filter((f) => !isNotRun(f)) ?? [];
  return (
    <li className="p-4 border-b border-line/60 last:border-0" data-stage={id} data-status={status}>
      <div className="flex items-center gap-2.5">
        <StageDot status={status} />
        <span className={`text-sm font-medium ${status === "pending" ? "text-faint" : ""}`}>{name}</span>
        <span className="text-xs text-mute">{LABEL[status]}</span>
        {state?.elapsedMs != null && <span className="mono text-faint text-xs">{state.elapsedMs < 1000 ? `${state.elapsedMs} ms` : `${(state.elapsedMs / 1000).toFixed(1)} s`}</span>}
        <span className="mono text-faint ml-auto">{id}</span>
      </div>
      {status === "pending" && <p className="text-xs text-faint mt-1 ml-[22px]">{what}</p>}
      {state?.message && status !== "pending" && <p className="text-xs text-mute mt-1.5 ml-[22px] break-words">{state.message ? <WithIds text={state.message} /> : null}</p>}
      {unrun.map((f) => {
        const cost = unrunCost(f, decision);
        return (
          <div key={f.id} className="mt-2 ml-[22px] text-xs border border-dashed border-quar/60 bg-quar/10 rounded-md p-2" data-testid="not-run">
            <p className="font-medium text-quar">Did not run: {f.id.replace("CHECK.NOT_RUN.", "").toLowerCase()}</p>
            <p className="text-mute mt-0.5">{f.title.replace(/^Check [\w_]+ did not run: /, "")}</p>
            <p className="mt-1">{cost ? <>Cost under this policy: <span className="font-medium">{cost.severity}, +{cost.points} risk points</span></> : "Cost: shown once the decision is made."}</p>
          </div>);
      })}
      {id === "S5" && state && state.status !== "running" && !shown.some((f) => f.source === "llm") && !unrun.length &&
        <p className="text-xs text-mute mt-1.5 ml-[22px]">No model-generated findings: {shown.length ? "the review stage reported only what is listed below" : "the review stage reported nothing"}.</p>}
      {id === "S5" && unrun.length > 0 && <p className="text-xs text-quar mt-1.5 ml-[22px]">No model review took place. The verdict rests on deterministic checks only.</p>}
      {shown.map((f, i) => <FindingRow key={f.id + i} f={f} view={view} />)}
    </li>
  );
}

export function FindingRow({ f, view }: { f: Finding; view: ArtifactView | null }) {
  const cls = view?.finding_classes[f.id];
  return (
    <details className="mt-2 ml-[22px] text-xs border border-line rounded-md bg-bg" data-testid="finding">
      <summary className="p-2 cursor-pointer flex items-center gap-2 flex-wrap">
        <Severity_ s={f.severity} /><span className="mono text-faint truncate">{f.id}</span>
        {f.source === "llm" && <span className="border border-accent/40 text-accent rounded px-1.5 py-px">model-generated, evidence-checked: {f.grounded ? "yes" : "no"}</span>}
        <span className="ml-auto text-faint">{f.score ? `+${f.score}` : "+0"}</span>
      </summary>
      <div className="px-2 pb-2 space-y-1.5">
        <p>{f.title}</p>
        <dl className="grid grid-cols-[110px_1fr] gap-x-2 gap-y-0.5 text-mute">
          <dt>Check</dt><dd>{f.category} · {f.source}</dd>
          <dt>Stage</dt><dd>{f.stage}</dd>
          <dt>Risk contribution</dt><dd>{f.score} point{f.score === 1 ? "" : "s"}</dd>
          <dt>Effect</dt><dd>{cls ? <span className={`border rounded px-1.5 py-px ${classColour[cls]}`}>{classLabel[cls]}</span> : <span className="text-faint">shown once the artifact is recorded</span>}</dd>
        </dl>
        {f.evidence.length > 0 && <div><p className="text-faint">Evidence</p>
          <ul className="mono space-y-0.5">{f.evidence.map((e, i) => <li key={i} className="break-all">{e.ref}{e.detail ? <span className="text-mute"> — {e.detail}</span> : null}</li>)}</ul></div>}
      </div>
    </details>
  );
}

export function IdentityPanel({ view }: { view: ArtifactView }) {
  const short = (s: string | null) => (s ? s.slice(0, 16) + "…" : "-");
  return (
    <section className="card mt-6" aria-label="Identity">
      <div className="card-h flex-col !items-start !gap-0">
        <h2 className="h-title">Identity (S1)</h2>
        <p className="text-xs text-faint">Merkle root <span className="mono">{view.merkle_root}</span> <span className="text-allow">computed</span>
          {view.claimed_origin && <> · claimed origin <span className="mono">{view.claimed_origin}</span> <span className="text-quar">declared</span></>}</p>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead><tr className="text-left text-xs text-faint"><th className="p-3">File</th><th>Size</th><th>SHA-256 <span className="text-allow">computed</span></th><th>{view.claimed_origin ? `Against ${view.claimed_origin}` : "Against a hub"}</th></tr></thead>
          <tbody>{view.files.map((f) => (
            <tr key={f.path} className="border-t border-line/60 align-top" data-testid="file-row">
              <td className="p-3 mono break-all">{f.path}</td>
              <td className="pr-3 tabular-nums text-mute">{f.size == null ? "-" : f.size.toLocaleString()}</td>
              <td className="pr-3 mono text-mute" title={f.sha256 ?? ""}>{short(f.sha256)}</td>
              <td className={`pr-3 font-medium ${originColour[f.origin]}`}>{f.origin === "unchecked" ? (view.origin_checked ? "not checked" : "no origin to check") : f.origin}</td>
            </tr>))}</tbody>
        </table>
      </div>
      {view.facts.length > 0 && (
        <div className="overflow-x-auto border-t border-line">
          <table className="w-full text-sm">
            <thead><tr className="text-left text-xs text-faint"><th className="p-3">Fact</th><th>Value</th><th>Class</th><th>Source</th></tr></thead>
            <tbody>{view.facts.map((f, i) => (
              <tr key={i} className="border-t border-line/60 align-top"><td className="p-3 mono">{f.key}</td>
                <td className="pr-3 break-all max-w-[360px]">{(f.value ?? "").slice(0, 120)}</td>
                <td className={`pr-3 font-medium ${provColour[f.provenance]}`}>{f.provenance}</td>
                <td className="pr-3 text-mute text-xs">{f.source}</td></tr>))}</tbody>
          </table>
          <p className="text-xs text-faint p-3">Only computed, fetched and signed facts can relax a check; declared facts only add risk.</p>
        </div>)}
    </section>
  );
}

export function DecisionPanel({ decision, view, env, findings, onChanged }: { decision: Decision; view: ArtifactView | null; env: string; findings: Finding[]; onChanged: () => void }) {
  const [open, setOpen] = useState<"approve" | "reject" | null>(null);
  const [reason, setReason] = useState("");
  const [days, setDays] = useState(7);
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const drivers = [...decision.findings].filter((f) => f.score > 0).sort((a, b) => b.score - a.score).slice(0, 5);
  const unrun = decision.findings.filter(isNotRun);
  const pending = view?.status === "quarantined";
  const canAct = auth.can("approver") && !view?.hard_block && pending;
  const act = async (kind: "approve" | "reject") => {
    setBusy(true); setErr(null);
    try {
      if (kind === "approve") await api.approve(decision.artifact_id, { reason: reason.trim(), expires: new Date(Date.now() + days * 86400000).toISOString() });
      else await api.reject(decision.artifact_id, reason.trim());
      setOpen(null); onChanged();
    } catch (e) { setErr(describeError(e)); } finally { setBusy(false); }
  };
  return (
    <section className="card mt-6 p-5" aria-live="polite" aria-label="Decision">
      <div className="flex flex-wrap gap-6 items-start">
        <div className="min-w-[200px]">
          <p className="text-sm text-mute mb-2">Verdict for {env} · policy <span className="mono">{decision.policy_version}</span></p>
          <Verdict outcome={decision.outcome} size="lg" />
          <div className="mt-4 flex flex-col gap-2 text-sm"><Trust level={decision.trust_level} /><Risk score={decision.risk_score} /></div>
        </div>
        <div className="flex-1 min-w-[260px]">
          <p className="text-sm text-mute mb-2">Why {view?.hard_block && <span className="text-block border border-block/40 rounded px-1.5 py-px text-xs ml-1">hard block</span>}</p>
          <Reasons primary={decision.primary_reason} secondary={decision.secondary_reasons} all={decision.reasons} />
          {decision.conditions.length > 0 && <p className="text-sm text-cond mt-2">Conditions: {decision.conditions.join("; ")}</p>}
        </div>
        <div className="min-w-[240px] flex-1">
          <p className="text-sm text-mute mb-2">Risk {decision.risk_score}: what contributed</p>
          <ul className="text-xs space-y-1">{drivers.length ? drivers.map((f) => <li key={f.id + f.title} className="flex gap-2"><Severity_ s={f.severity} /><span className="mono truncate">{f.id}</span><span className="ml-auto text-mute">+{f.score}</span></li>) : <li className="text-faint">No finding added points; trust level {decision.trust_level} sets the base.</li>}</ul>
          {unrun.length > 0 && <>
            <p className="text-sm text-mute mt-3 mb-1">Checks that did not run</p>
            <ul className="text-xs space-y-1">{unrun.map((f) => <li key={f.id} className="flex gap-2"><span className="mono truncate">{f.id.replace("CHECK.NOT_RUN.", "")}</span><span className="ml-auto text-mute">{f.severity}, +{f.score}</span></li>)}</ul></>}
        </div>
      </div>
      <div className="mt-5 border-t border-line pt-4">
        <p className="text-sm"><span className="text-mute">Next: </span>{view?.next_action ?? "…"}</p>
        {canAct && (
          <div className="mt-3">
            <div className="flex gap-2">
              <button className="btn btn-primary" onClick={() => setOpen("approve")} disabled={busy}>Approve…</button>
              <button className="btn btn-danger" onClick={() => setOpen("reject")} disabled={busy}>Reject…</button>
            </div>
            {open && (
              <form className="mt-3 grid sm:grid-cols-[1fr_140px_auto] gap-3 items-end" onSubmit={(e) => { e.preventDefault(); if (reason.trim().length > 2) act(open); }}>
                <label className="text-xs text-mute">Reason (recorded with your name)<input className="input mt-1" value={reason} onChange={(e) => setReason(e.target.value)} /></label>
                {open === "approve" ? <label className="text-xs text-mute">Approval lasts<select className="input mt-1" value={days} onChange={(e) => setDays(+e.target.value)}>{[1, 3, 7, 30].map((d) => <option key={d} value={d}>{d} day{d > 1 ? "s" : ""}</option>)}</select></label> : <span className="text-xs text-faint">Rejecting refuses this request and records your reason and name. Nothing is revoked; the history stays.</span>}
                <button className={`btn ${open === "approve" ? "btn-primary" : "btn-danger"}`} disabled={busy || reason.trim().length < 3}>{busy ? "Working…" : open === "approve" ? "Approve" : "Reject"}</button>
              </form>)}
            {err && <p className="text-sm text-block mt-2" role="alert" data-testid="act-error">{err}</p>}
          </div>)}
        {findings.length > 0 && <p className="text-xs text-faint mt-3">{findings.length} finding{findings.length === 1 ? "" : "s"} across the stages.</p>}
      </div>
    </section>
  );
}

const keyStatus: Record<string, string> = {
  trusted_in_scope: "trusted for this source (in the key's scope)", not_a_trusted_publisher: "NOT a trusted publisher: treated as unsigned", outside_scope: "trusted key, but signing OUTSIDE its scope: treated as unsigned",
  revoked: "REVOKED key: treated as unsigned", trusted_key: "trusted key", unknown_key: "unknown",
};

function Pill({ ok, children }: { ok: boolean | null; children: React.ReactNode }) {
  const c = ok === null ? "text-faint border-line" : ok ? "text-allow border-allow/40" : "text-block border-block/40";
  return <span className={`border rounded px-1.5 py-px text-xs ${c}`}>{children}</span>;
}

export function PassportPanel({ view, decision, env }: { view: ArtifactView; decision: Decision; env: string }) {
  const [tab, setTab] = useState<"passport" | "attestation" | "checks">("checks");
  const [passport, setPassport] = useState<SignedPassport | null>(null);
  const [att, setAtt] = useState<AttestationView | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [copied, setCopied] = useState<string | null>(null);
  useEffect(() => {
    setErr(null);
    api.passport(decision.artifact_id).then(setPassport).catch((e) => setErr(describeError(e)));
    api.attestationView(decision.artifact_id, env).then(setAtt).catch((e) => setErr(describeError(e)));
  }, [decision.artifact_id, decision.outcome, env]);
  const copy = (key: string, text: string) => { navigator.clipboard?.writeText(text).then(() => { setCopied(key); setTimeout(() => setCopied(null), 1500); }).catch(() => {}); };
  const pj = passport ? JSON.stringify(passport, null, 2) : "";
  const download = (name: string, text: string) => { const a = document.createElement("a"); a.href = URL.createObjectURL(new Blob([text], { type: "application/json" })); a.download = name; a.click(); URL.revokeObjectURL(a.href); };
  const cp = view.creator_passport;
  const a = att?.attestation.attestation;
  const matches = view.files.filter((f) => f.origin !== "unchecked");
  const bytesOk = cp.present && cp.bytes_match != null ? cp.bytes_match : null;
  return (
    <section className="card mt-6" aria-label="Passport and attestation">
      <div className="card-h"><h2 className="h-title">Passport and attestation</h2>
        <div className="flex gap-1" role="tablist">{(["checks", "passport", "attestation"] as const).map((t) =>
          <button key={t} role="tab" aria-selected={tab === t} className={`btn ${tab === t ? "btn-primary" : ""}`} onClick={() => setTab(t)}>{t === "checks" ? "Five checks" : t === "passport" ? "Passport JSON" : "Attestation"}</button>)}</div></div>
      <div className="p-4">
        {err && <p className="text-sm text-block mb-2">{err}</p>}
        {tab === "checks" && (
          <ol className="space-y-3 text-sm" data-testid="five-checks">
            <li><span className="text-mute">1. Claimed publisher </span><Pill ok={null}>declared</Pill><p className="mt-1">{cp.present ? <>{cp.claimed_publisher || "none named"} <span className="text-faint">(from the creator passport; anyone can write this)</span></> : "No creator passport was supplied."}</p></li>
            <li><span className="text-mute">2. Signature verifies against the signer's key{cp.key_id ? <> (key <span className="mono">{cp.key_id}</span>)</> : null} </span><Pill ok={cp.signature === "valid" ? true : cp.signature === "invalid" ? false : null}>{cp.present ? (cp.signature === "not_checked" ? "not checked" : cp.signature) : "no passport"}</Pill>
              {cp.signature === "not_checked" && <p className="mt-1 text-faint">The signing key is not one the policy trusts, so the signature was not used.</p>}</li>
            <li><span className="text-mute">3. Key trusted for this source </span><Pill ok={cp.key_status === "trusted_in_scope" ? true : cp.present ? false : null}>{cp.present ? (cp.key_status ?? "unknown") : "n/a"}</Pill>
              {cp.present && <p className="mt-1">{keyStatus[cp.key_status ?? "unknown"] ?? cp.key_status}{cp.signer ? ` · ${cp.signer}` : ""}{cp.claimed_source ? ` · claims ${cp.claimed_source}` : ""} <span className="text-faint">(trusted publishers and their scope are set in the policy, never by the upload)</span></p>}</li>
            <li><span className="text-mute">4. Bytes match the hashes </span><Pill ok={view.files.some((f) => f.origin === "changed" || f.origin === "missing") ? false : bytesOk ?? (matches.length ? true : null)}>
              {view.files.some((f) => f.origin === "changed" || f.origin === "missing") ? "differs from the hub" : bytesOk != null ? (bytesOk ? "match the passport" : "do not match the passport") : matches.length ? "match the hub" : "nothing to compare with"}</Pill></li>
            <li><span className="text-mute">5. The organisation's attestation </span><Pill ok={a ? (a.outcome === "allow" || a.outcome === "allow_with_conditions") && !a.revoked && att!.signature_ok : null}>{a ? `${a.outcome} for ${a.environment}${a.revoked ? " (revoked)" : ""}` : "loading"}</Pill>
              {a && <p className="mt-1 text-faint">Issued {dt(a.issued_at)}, expires {dt(a.expires_at)}. This is the only statement the loader trusts.</p>}</li>
          </ol>)}
        {tab === "passport" && (passport ? (
          <div>
            <div className="flex gap-2 mb-2"><button className="btn" onClick={() => copy("p", pj)}>{copied === "p" ? "Copied" : "Copy"}</button><button className="btn" onClick={() => download(`${decision.artifact_id.replace(":", "_")}.passport.json`, pj)}>Download</button></div>
            <details open><summary className="text-xs text-faint cursor-pointer">The registry's passport for this intake (what Lineage found and signed)</summary>
              <pre className="text-xs mono bg-bg border border-line rounded-md p-3 overflow-auto max-h-[420px] mt-2" data-testid="passport-json">{pj}</pre></details>
          </div>) : <p className="text-sm text-faint">Loading…</p>)}
        {tab === "attestation" && (att && a ? (
          <dl className="grid grid-cols-[170px_1fr] gap-y-1.5 text-sm" data-testid="attestation">
            <dt className="text-mute">Environment</dt><dd>{a.environment}</dd>
            <dt className="text-mute">Outcome</dt><dd><Verdict outcome={a.outcome} />{a.revoked && <span className="text-block ml-2">revoked</span>}</dd>
            <dt className="text-mute">Policy version</dt><dd className="mono">{a.policy_version}</dd>
            <dt className="text-mute">Issued / expires</dt><dd>{dt(a.issued_at)} / {dt(a.expires_at)}</dd>
            <dt className="text-mute">Signing key</dt><dd className="mono">{att.attestation.key_id}</dd>
            <dt className="text-mute">Signature</dt><dd><Pill ok={att.signature_ok}>{att.signature_ok ? "verifies" : "does NOT verify"}</Pill> <span className="text-faint text-xs">checked by {att.verified_by}; `lineage pull` checks it against the key you pinned</span></dd>
          </dl>) : <p className="text-sm text-faint">Loading…</p>)}
        {view.pull_command && (
          <div className="mt-5 border-t border-line pt-4" data-testid="pull">
            <p className="text-sm text-mute mb-1">Use it: pull the registry's copy (the CLI reads <span className="mono">LINEAGE_TOKEN</span>; no token is in this command)</p>
            <code className="block mono text-xs bg-bg border border-line rounded-md p-2 break-all">{view.pull_command}</code>
            <div className="flex gap-2 mt-2 items-center"><button className="btn" onClick={() => copy("c", view.pull_command!)}>{copied === "c" ? "Copied" : "Copy"}</button>
              <button className="btn" onClick={() => copy("f", view.pull_command_first_use!)}>{copied === "f" ? "Copied" : "Copy first-use (--pin)"}</button>
              <span className="text-xs text-faint">The command is a convenience; the server stays the boundary.</span></div>
          </div>)}
      </div>
    </section>
  );
}
