import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../lib/api";
import { useAsync } from "../lib/useAsync";
import { ago, statusOutcome, verdictKey } from "../lib/format";
import { useMonitorIds } from "../lib/monitor";
import type { ArtifactType, Outcome } from "../lib/types";
import { Empty, ErrorBox, Header, Loading, Risk, StatusPill, Trust, TypeTag, Verdict } from "../components/ui";

const types: ArtifactType[] = ["dataset", "model", "package", "tool", "agent"];
const outcomes: Outcome[] = ["allow", "allow_with_conditions", "quarantine", "block"];

export default function Catalogue() {
  const { data, error, reload } = useAsync(api.artifacts);
  const monitorIds = useMonitorIds();
  const [q, setQ] = useState("");
  const [type, setType] = useState("");
  const [outcome, setOutcome] = useState("");
  const rows = useMemo(() => (data ?? []).filter((a) =>
    (!q || `${a.name} ${a.version}`.toLowerCase().includes(q.toLowerCase())) &&
    (!type || a.artifact_type === type) &&
    (!outcome || (a.outcome ?? statusOutcome[a.status]) === outcome)), [data, q, type, outcome]);

  return (
    <div className="page">
      <Header title="Catalogue" sub="Every artifact Lineage has decided on, with its latest verdict." actions={<Link to="/intake" className="btn btn-primary">New intake</Link>} />
      {error && <ErrorBox msg={error} retry={reload} />}
      {!data && !error && <Loading />}
      {data && (
        <div className="card">
          <div className="card-h">
            <input className="input max-w-xs" placeholder="Search by name" aria-label="Search artifacts" value={q} onChange={(e) => setQ(e.target.value)} />
            <div className="flex gap-2">
              <select className="input !w-32" aria-label="Filter by type" value={type} onChange={(e) => setType(e.target.value)}>
                <option value="">All types</option>{types.map((t) => <option key={t} value={t}>{t}</option>)}
              </select>
              <select className="input !w-44" aria-label="Filter by decision" value={outcome} onChange={(e) => setOutcome(e.target.value)}>
                <option value="">All decisions</option>{outcomes.map((o) => <option key={o} value={o}>{o.replace(/_/g, " ")}</option>)}
              </select>
            </div>
          </div>
          {rows.length === 0 ? <Empty title="No artifacts match" hint="Clear the filters or submit a new artifact." /> : (
            <div className="overflow-x-auto"><table className="w-full">
              <thead><tr><th className="th">Name</th><th className="th">Type</th><th className="th">Trust</th><th className="th w-40">Risk</th><th className="th">Decision</th><th className="th">Status</th><th className="th">Env</th><th className="th">Added</th></tr></thead>
              <tbody>{rows.map((a) => (
                <tr key={a.id} className="hover:bg-raised/50">
                  <td className="td"><Link className="font-medium hover:text-accent" to={`/artifacts/${encodeURIComponent(a.id)}`}>{a.name}</Link><span className="text-faint ml-1.5 mono">{a.version}</span></td>
                  <td className="td"><TypeTag t={a.artifact_type} /></td>
                  <td className="td"><Trust level={a.trust_level} /></td>
                  <td className="td"><Risk score={a.risk_score} /></td>
                  <td className="td"><Verdict outcome={verdictKey(a.status, a.outcome, a.id, monitorIds)} /></td>
                  <td className="td"><StatusPill status={a.status} /></td>
                  <td className="td text-mute">{a.environment}</td>
                  <td className="td text-mute whitespace-nowrap">{ago(a.created_at)}</td>
                </tr>))}</tbody></table></div>)}
        </div>)}
    </div>
  );
}
