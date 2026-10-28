import { api } from "../lib/api";
import { useAsync } from "../lib/useAsync";
import { Empty, ErrorBox, Header, Loading } from "../components/ui";

export default function TrustedPublishers() {
  const { data, error, reload } = useAsync(api.trustedPublishers);
  if (error) return <div className="page"><ErrorBox msg={error} retry={reload} /></div>;
  if (!data) return <div className="page"><Loading /></div>;
  return (
    <div className="page">
      <Header title="Trusted publishers" sub="Signing keys the policy trusts, and the sources each may speak for. Read-only: changing this list is a policy change and needs 2 of 3 role signatures." />
      <section className="card">
        {data.publishers.length === 0 ? <Empty title="No trusted publishers in the policy" hint="Creator passports count for nothing until a key is listed here." /> : (
          <table className="w-full text-sm"><thead><tr className="text-left text-xs text-faint"><th className="p-3">Publisher</th><th>Key id</th><th>Scope</th><th>Status</th></tr></thead>
            <tbody>{data.publishers.map((p) => (
              <tr key={p.key_id} className="border-t border-line/60 align-top"><td className="p-3 font-medium">{p.name}</td><td className="mono">{p.key_id}</td>
                <td className="mono text-xs">{p.scope.join(", ") || "(none)"}</td><td className={p.revoked ? "text-block" : "text-allow"}>{p.revoked ? "revoked" : "active"}</td></tr>))}</tbody></table>)}
      </section>
      {data.bootstrap_keys.length > 0 && <p className="text-sm text-quar mt-4">Dev bootstrap keys from LINEAGE_TRUSTED_KEYS are trusted for any scope while the policy lists no publishers: {data.bootstrap_keys.join(", ")}.</p>}
    </div>
  );
}
