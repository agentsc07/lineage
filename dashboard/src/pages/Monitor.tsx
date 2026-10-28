import { api } from "../lib/api";
import { useAsync } from "../lib/useAsync";
import { dt } from "../lib/format";
import { Empty, ErrorBox, Header, Loading } from "../components/ui";

export default function Monitor() {
  const status = useAsync(api.monitorStatus);
  const latest = useAsync(api.latestTick);
  if (status.error) return <div className="page"><ErrorBox msg={status.error} retry={status.reload} /></div>;
  if (!status.data) return <div className="page"><Loading /></div>;
  const s = status.data;
  return (
    <div className="page">
      <Header title="Monitor" sub="A scheduled tick re-checks advisories (ghost packages included), hub drift, revoked keys, expired approvals and policy changes." />
      <section className="card p-4 flex flex-wrap gap-8 text-sm">
        <div><p className="text-faint text-xs">Last tick</p><p>{s.last ? dt(s.last) : "never"}</p></div>
        <div><p className="text-faint text-xs">Next tick</p><p>{s.next ? dt(s.next) : "not scheduled"}</p></div>
        <div><p className="text-faint text-xs">Interval</p><p>{s.interval_minutes > 0 ? `${s.interval_minutes} min` : "off (LINEAGE_MONITOR_MINUTES=0)"}</p></div>
      </section>
      <section className="card mt-4">
        <div className="card-h"><h2 className="h-title">Alerts <span className="text-faint font-normal">(latest tick that raised any)</span></h2></div>
        {!latest.data || latest.data.alerts.length === 0 ? <Empty title="No alerts" hint="Nothing has changed since admission." /> : latest.data.alerts.map((a, i) => (
          <div key={i} className="p-4 border-b border-line/60 last:border-0">
            <p className="text-sm"><span className="mono text-faint mr-2">{a.kind}</span><span className={a.severity === "high" || a.severity === "critical" ? "text-block" : ""}>{a.severity}</span></p>
            <p className="text-sm mt-1">{a.message}</p>
            {a.blast_radius.length > 0 && <p className="text-xs text-mute mt-1">Blast radius: {a.blast_radius.map((n) => n.label).join(", ")}</p>}
          </div>))}
      </section>
    </div>
  );
}
