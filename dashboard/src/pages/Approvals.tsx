import { useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../lib/api";
import { useAsync } from "../lib/useAsync";
import { session, useSession } from "../lib/session";
import { ago, dt } from "../lib/format";
import { Empty, ErrorBox, Header, Risk, Verdict } from "../components/ui";

const inDays = (n: number) => new Date(Date.now() + n * 864e5).toISOString().slice(0, 10);

export default function Approvals() {
  const arts = useAsync(api.artifacts);
  const sess = useSession();
  const [open, setOpen] = useState<string | null>(null);
  const [approver, setApprover] = useState("");
  const [reason, setReason] = useState("");
  const [expires, setExpires] = useState(inDays(30));
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [localApproved, setLocalApproved] = useState<Record<string, string>>({});

  const queue = [
    ...sess.filter((s) => s.decision.outcome === "quarantine").map((s) => ({ id: s.decision.artifact_id, name: s.ref, type: s.artifact_type, risk: s.decision.risk_score, env: s.decision.environment, reasons: s.decision.reasons, at: s.decision.decided_at, approved: s.approved?.by ? `${s.approved.by} until ${s.approved.expires}` : localApproved[s.decision.artifact_id] })),
    ...(arts.data ?? []).filter((a) => a.status === "quarantined").map((a) => ({ id: a.id, name: `${a.name}@${a.version}`, type: a.artifact_type, risk: a.risk_score, env: a.environment, reasons: [] as string[], at: a.created_at, approved: localApproved[a.id] })),
  ];
  const pending = queue.filter((q) => !q.approved);
  const finished = queue.filter((q) => q.approved);

  const submit = async (id: string) => {
    setBusy(true); setErr(null);
    try {
      const d = await api.approve(id, { approver: approver.trim(), reason: reason.trim(), expires: new Date(expires + "T23:59:59Z").toISOString() });
      session.approve(id, { by: approver.trim(), reason: reason.trim(), expires }, d);
      setLocalApproved((m) => ({ ...m, [id]: `${approver.trim()} until ${expires}` }));
      setOpen(null); setReason("");
    } catch (e: any) { setErr(e.message); } finally { setBusy(false); }
  };
  const valid = approver.trim() && reason.trim().length >= 8 && expires;

  return (
    <div className="page">
      <Header title="Approvals" sub="Quarantined artifacts wait here for a person. An approval needs a reason and always expires." />
      {arts.error && <ErrorBox msg={arts.error} retry={arts.reload} />}
      <section className="card">
        <div className="card-h"><h2 className="h-title">Waiting for review <span className="text-faint font-normal">({pending.length})</span></h2></div>
        {pending.length === 0 ? <Empty title="Nothing to review" hint="Quarantined artifacts from intake appear here."><Link to="/intake" className="btn">New intake</Link></Empty> :
          pending.map((q) => (
            <div key={q.id + q.at} className="p-4 border-b border-line/60 last:border-0">
              <div className="flex flex-wrap items-center gap-4">
                <div className="min-w-[200px] flex-1">
                  <Link to={`/artifacts/${encodeURIComponent(q.id)}`} className="font-medium hover:text-accent">{q.name}</Link>
                  <p className="text-xs text-mute mt-0.5 capitalize">{q.type} · for {q.env} · {ago(q.at)}</p>
                </div>
                <Verdict outcome="quarantine" /><div className="w-32"><Risk score={q.risk} /></div>
                <button className="btn btn-primary" onClick={() => { setOpen(open === q.id + q.at ? null : q.id + q.at); setErr(null); }}>Review</button>
              </div>
              {q.reasons.length > 0 && <ul className="text-sm text-mute list-disc pl-4 mt-3 space-y-0.5">{q.reasons.map((r, i) => <li key={i}>{r}</li>)}</ul>}
              {open === q.id + q.at && (
                <form className="mt-4 grid sm:grid-cols-[180px_1fr_160px_auto] gap-3 items-end bg-raised/50 border border-line rounded-md p-3" onSubmit={(e) => { e.preventDefault(); if (valid) submit(q.id); }}>
                  <label className="text-sm text-mute">Approver<input className="input mt-1" value={approver} onChange={(e) => setApprover(e.target.value)} placeholder="name@apollo.health" /></label>
                  <label className="text-sm text-mute">Reason<input className="input mt-1" value={reason} onChange={(e) => setReason(e.target.value)} placeholder="Why this is safe to use" /></label>
                  <label className="text-sm text-mute">Expires<input type="date" className="input mt-1" value={expires} min={inDays(1)} onChange={(e) => setExpires(e.target.value)} /></label>
                  <button className="btn btn-primary" disabled={!valid || busy}>{busy ? "Approving…" : "Approve"}</button>
                  {err && <p className="text-sm text-block sm:col-span-4">{err}</p>}
                </form>)}
            </div>))}
      </section>
      {finished.length > 0 && (
        <section className="card mt-4">
          <div className="card-h"><h2 className="h-title">Approved this session</h2></div>
          {finished.map((q) => <div key={q.id + q.at} className="px-4 py-3 border-b border-line/60 last:border-0 flex justify-between gap-4 text-sm"><span className="font-medium">{q.name}</span><span className="text-mute">{q.approved} · {dt(q.at)}</span></div>)}
        </section>)}
    </div>
  );
}
