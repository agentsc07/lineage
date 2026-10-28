import { useState } from "react";
import { api } from "../lib/api";
import { useAsync } from "../lib/useAsync";
import { Empty, ErrorBox, Header, Loading } from "../components/ui";

export default function Federated() {
  const clients = useAsync(api.flClients);
  const rounds = useAsync(api.flRounds);
  const [sel, setSel] = useState<string | null>(null);
  const round = useAsync(async () => (sel ? api.flRound(sel) : null), [sel]);
  if (clients.error) return <div className="page"><ErrorBox msg={clients.error} retry={clients.reload} /></div>;
  if (!clients.data || !rounds.data) return <div className="page"><Loading /></div>;
  const z = round.data?.z ?? {};
  const keys = ["norm", "cosine_distance", "krum", "sign_disagreement"];
  return (
    <div className="page">
      <Header title="Federated" sub="Each client update is scored (norm, cosine distance to the median, Krum, sign agreement); clients lose trust when flagged and are quarantined below 0.3." />
      <div className="grid lg:grid-cols-2 gap-4 items-start">
        <section className="card">
          <div className="card-h"><h2 className="h-title">Rounds <span className="text-faint font-normal">({rounds.data.length})</span></h2></div>
          {rounds.data.length === 0 ? <Empty title="No rounds yet" hint="POST /fl/rounds with one update per client." /> : (
            <ul>{rounds.data.map((r) => <li key={r}><button className={`w-full text-left px-4 py-2 border-b border-line/60 hover:bg-raised/60 mono text-sm ${sel === r ? "bg-raised" : ""}`} onClick={() => setSel(r)}>{r}</button></li>)}</ul>)}
        </section>
        <section className="card">
          <div className="card-h"><h2 className="h-title">Clients</h2></div>
          {clients.data.length === 0 ? <Empty title="No clients yet" /> : (
            <table className="w-full text-sm"><thead><tr className="text-left text-xs text-faint"><th className="p-3">Client</th><th>Trust</th><th>Flagged</th><th>Clean</th><th>State</th></tr></thead>
              <tbody>{clients.data.map((c) => (
                <tr key={c.client_id} className="border-t border-line/60" title={c.reasons.slice(-3).join("; ")}><td className="p-3 mono">{c.client_id}</td>
                  <td><span className="inline-block h-1.5 rounded bg-accent align-middle mr-2" style={{ width: `${Math.round(c.trust * 60)}px` }} />{c.trust.toFixed(2)}</td>
                  <td>{c.flagged_rounds}</td><td>{c.clean_rounds}</td><td className={c.quarantined ? "text-block font-medium" : "text-allow"}>{c.quarantined ? "quarantined" : "active"}</td></tr>))}</tbody></table>)}
        </section>
      </div>
      {round.data && (
        <section className="card mt-4">
          <div className="card-h"><h2 className="h-title">Round {round.data.round_id} <span className="text-faint font-normal">{round.data.mode}, {round.data.aggregator}</span></h2></div>
          {round.data.notes.map((n) => <p key={n} className="px-4 py-2 text-sm text-quar">{n}</p>)}
          <table className="w-full text-sm"><thead><tr className="text-left text-xs text-faint"><th className="p-3">Client</th>{keys.map((k) => <th key={k}>z {k}</th>)}<th>Flagged</th></tr></thead>
            <tbody>{Object.entries(z).map(([c, s]) => (
              <tr key={c} className="border-t border-line/60"><td className="p-3 mono">{c}</td>
                {keys.map((k) => <td key={k} className={s[k] > 3 ? "text-block font-medium" : ""}>{s[k]?.toFixed(1)}</td>)}
                <td className="text-xs">{round.data!.flagged[c]?.join("; ") ?? ""}</td></tr>))}
              {round.data.excluded.map((c) => <tr key={c} className="border-t border-line/60 text-faint"><td className="p-3 mono">{c}</td><td colSpan={5}>quarantined: excluded from this round</td></tr>)}</tbody></table>
        </section>)}
    </div>
  );
}
