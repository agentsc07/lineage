import { Link } from "react-router-dom";
import { useEffect, useState } from "react";
import { api } from "../lib/api";
import { useAsync } from "../lib/useAsync";
import { useSession } from "../lib/session";
import { ago, shortId, statusOutcome, verdictKey, type VerdictKey } from "../lib/format";
import { useMonitorIds } from "../lib/monitor";
import type { MonitorTick, Outcome } from "../lib/types";
import { Empty, ErrorBox, Header, Kpi, Loading, Risk, Severity_, TypeTag, Verdict } from "../components/ui";

export default function Overview() {
  const arts = useAsync(api.artifacts);
  const sess = useSession();
  const monitorIds = useMonitorIds();
  const [tick, setTick] = useState<MonitorTick | null>(null);
  const [ticking, setTicking] = useState(false);
  const [tickErr, setTickErr] = useState<string | null>(null);

  // A tick with nothing new is quiet (ticks are idempotent), so keep showing the latest tick that raised alerts.
  const check = () => {
    setTicking(true);
    api.tick()
      .then(async (t) => { setTick(t.alerts.length ? t : (await api.latestTick()) ?? t); setTickErr(null); })
      .catch((e) => setTickErr(String(e.message))).finally(() => setTicking(false));
  };
  useEffect(() => { api.latestTick().then((t) => t && setTick(t)).catch(() => {}).finally(check); }, []);

  if (arts.error) return <div className="page"><ErrorBox msg={arts.error} retry={arts.reload} /></div>;
  if (!arts.data) return <div className="page"><Loading /></div>;
  const rows = arts.data;
  const count = (o: Outcome) => rows.filter((a) => (a.status === "revoked" ? "block" : a.outcome ?? statusOutcome[a.status]) === o).length + sess.filter((s) => s.decision.outcome === o).length;
  const total = rows.length + sess.length;
  const avg = rows.length ? Math.round(rows.reduce((s, a) => s + a.risk_score, 0) / rows.length) : 0;

  // Recent decisions: this session's intake results first, then the catalogue.
  const recent = [
    ...sess.map((s) => ({ key: s.decision.artifact_id + s.decision.decided_at, name: s.ref, type: s.artifact_type, outcome: (s.approved ? "allow_with_conditions" : s.decision.outcome) as VerdictKey, risk: s.decision.risk_score, env: s.decision.environment, at: s.decision.decided_at, id: s.decision.artifact_id })),
    ...rows.map((a) => ({ key: a.id, name: `${a.name}@${a.version}`, type: a.artifact_type, outcome: verdictKey(a.status, a.outcome, a.id, monitorIds) as VerdictKey, risk: a.risk_score, env: a.environment, at: a.created_at, id: a.id })),
  ].sort((a, b) => Date.parse(b.at) - Date.parse(a.at)).slice(0, 8);

  return (
    <div className="page">
      <Header title="Overview" sub="What has been admitted, what is waiting on a person, and what the monitor has flagged since." />
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
        <Kpi label="Artifacts" value={total} sub={`mean risk ${avg}/100`} />
        <Kpi label="Allowed" value={count("allow") + count("allow_with_conditions")} tone="allow" />
        <Kpi label="Awaiting a reviewer" value={count("quarantine")} tone="quar" sub="Quarantined, needs approval" />
        <Kpi label="Blocked" value={count("block")} tone="block" />
      </div>
      <div className="grid lg:grid-cols-[1fr_340px] gap-4 items-start">
        <section className="card">
          <div className="card-h"><h2 className="h-title">Recent decisions</h2><Link to="/catalogue" className="text-sm text-accent hover:underline">View catalogue</Link></div>
          {recent.length === 0 ? <Empty title="No decisions yet" hint="Submit an artifact to see its verdict here."><Link className="btn btn-primary" to="/intake">New intake</Link></Empty> : (
            <table className="w-full"><thead><tr><th className="th">Artifact</th><th className="th">Decision</th><th className="th w-36">Risk</th><th className="th">Env</th><th className="th">When</th></tr></thead>
              <tbody>{recent.map((r) => (
                <tr key={r.key} className="hover:bg-raised/50">
                  <td className="td"><Link to={`/artifacts/${encodeURIComponent(r.id)}`} className="font-medium hover:text-accent">{r.name}</Link> <TypeTag t={r.type as any} /></td>
                  <td className="td"><Verdict outcome={r.outcome} /></td>
                  <td className="td"><Risk score={r.risk} /></td>
                  <td className="td text-mute">{r.env}</td>
                  <td className="td text-mute whitespace-nowrap">{ago(r.at)}</td>
                </tr>))}</tbody></table>)}
        </section>
        <section className="card">
          <div className="card-h"><h2 className="h-title">Monitor alerts</h2><button className="btn !h-7" onClick={check} disabled={ticking}>{ticking ? "Checking…" : "Check now"}</button></div>
          {tickErr && <p className="p-4 text-sm text-block">{tickErr}</p>}
          {tick && tick.alerts.length === 0 && <Empty title="All clear" hint={`${tick.checked} admitted artifacts re-checked.`} />}
          {tick?.alerts.map((a, i) => (
            <div key={i} className="p-4 border-b border-line/60 last:border-0">
              <div className="flex items-center gap-2 mb-1"><Severity_ s={a.severity} /><span className="text-xs text-mute capitalize">{a.kind}</span></div>
              <p className="text-sm">{a.message}</p>
              {a.blast_radius.length > 0 && <p className="text-xs text-mute mt-2">Affects {a.blast_radius.map((n) => n.label).join(", ")}</p>}
              <Link to={`/graph/${encodeURIComponent(a.artifact_id)}`} className="text-sm text-accent hover:underline mt-2 inline-block">See blast radius <span className="mono text-faint">{shortId(a.artifact_id)}</span></Link>
            </div>))}
          {tick && <p className="px-4 py-2 text-xs text-faint">Checked {tick.checked} artifacts {ago(tick.ts)}</p>}
        </section>
      </div>
    </div>
  );
}
