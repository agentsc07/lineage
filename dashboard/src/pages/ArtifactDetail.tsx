import { useParams, Link } from "react-router-dom";
import { useState } from "react";
import { api } from "../lib/api";
import { useAsync } from "../lib/useAsync";
import { dt, sevMeta, shortId, statusOutcome } from "../lib/format";
import type { Finding } from "../lib/types";
import Snippet from "../components/Snippet";
import { Empty, ErrorBox, Loading, Risk, Severity_, StatusPill, Trust, TypeTag, Verdict } from "../components/ui";

export default function ArtifactPage() {
  const { id = "" } = useParams();
  const { data, error, reload } = useAsync(() => api.artifact(id), [id]);
  const policy = useAsync(api.policy);
  const [verify, setVerify] = useState<string | null>(null);

  if (error) return <div className="page"><ErrorBox msg={error} retry={reload} /></div>;
  if (!data) return <div className="page"><Loading /></div>;
  const { artifact: a, passport, decision } = data;
  const findings: Finding[] = (data.findings.length ? data.findings : decision?.findings ?? []).slice().sort((x, y) => sevMeta[y.severity].rank - sevMeta[x.severity].rank);
  const body = passport?.passport.predicate;
  const cmap: Record<string, string[]> = policy.data?.policy.compliance_map ?? {};
  const controlsFor = (cat: string) => Object.entries(cmap).filter(([, cats]) => cats.includes(cat)).map(([c]) => c);
  const controls = [...new Set(findings.flatMap((f) => controlsFor(f.category)))];

  const runVerify = () => fetch(`/api/passports/${encodeURIComponent(id)}/verify`).then((r) => r.json()).then((v) =>
    setVerify(v.valid ? "Signature, hashes and chain verified" : `Not valid: ${(v.problems ?? []).join(", ") || "see server log"}`)).catch((e) => setVerify(String(e)));

  return (
    <div className="page">
      <div className="mb-6">
        <Link to="/catalogue" className="text-sm text-mute hover:text-ink">← Catalogue</Link>
        <div className="flex flex-wrap items-center gap-3 mt-2">
          <h1 className="text-xl font-semibold tracking-tight">{a.name}<span className="mono text-faint ml-2">{a.version}</span></h1>
          <TypeTag t={a.artifact_type} /><StatusPill status={a.status} />
          <Link to={`/graph/${encodeURIComponent(a.id)}`} className="btn ml-auto">View lineage</Link>
        </div>
      </div>

      <div className="grid lg:grid-cols-[1fr_380px] gap-4 items-start">
        <div className="flex flex-col gap-4 min-w-0">
          <section className="card p-5">
            <div className="flex flex-wrap gap-6 items-start">
              <div>
                <p className="text-sm text-mute mb-2">Decision for {decision?.environment ?? a.environment}</p>
                <Verdict outcome={decision?.outcome ?? a.outcome ?? statusOutcome[a.status]} size="lg" />
              </div>
              <div className="flex flex-col gap-2"><Trust level={a.trust_level} /><Risk score={a.risk_score} /></div>
              {decision?.approver && <p className="text-sm text-mute">Approved by <span className="text-ink">{decision.approver}</span></p>}
            </div>
            {decision && (<div className="mt-5 grid sm:grid-cols-2 gap-6">
              <div><h3 className="text-sm text-mute mb-2">Reasons</h3>
                <ul className="text-sm list-disc pl-4 space-y-1">{decision.reasons.length ? decision.reasons.map((r, i) => <li key={i}>{r}</li>) : <li className="text-faint list-none -ml-4">None recorded</li>}</ul></div>
              <div><h3 className="text-sm text-mute mb-2">Conditions</h3>
                {decision.conditions.length ? <ul className="text-sm list-disc pl-4 space-y-1 text-cond">{decision.conditions.map((r, i) => <li key={i}>{r}</li>)}</ul> : <p className="text-sm text-faint">No conditions</p>}</div>
            </div>)}
            {decision && <p className="text-xs text-faint mt-4">Decided {dt(decision.decided_at)} under policy <span className="mono">{decision.policy_version}</span></p>}
          </section>

          <section className="card">
            <div className="card-h"><h2 className="h-title">Findings <span className="text-faint font-normal">({findings.length})</span></h2></div>
            {findings.length === 0 ? <Empty title="No findings" hint="Every check passed for this artifact." /> : findings.map((f) => (
              <article key={f.id + f.stage} className="p-4 border-b border-line/60 last:border-0">
                <div className="flex flex-wrap items-center gap-2 mb-1.5">
                  <Severity_ s={f.severity} /><h3 className="text-sm font-medium">{f.title}</h3>
                </div>
                <div className="flex flex-wrap gap-x-4 gap-y-1 text-xs text-mute mb-3">
                  <span className="mono">{f.id}</span><span>{f.stage}</span><span className="capitalize">{f.source}{f.source === "llm" && (f.grounded ? ", citation verified" : ", ungrounded")}</span><span>+{f.score} risk</span>
                </div>
                <div className="flex flex-col gap-2">{f.evidence.map((e, i) => <Snippet key={i} ev={e} />)}</div>
              </article>))}
          </section>
        </div>

        <aside className="flex flex-col gap-4">
          <section className="card">
            <div className="card-h"><h2 className="h-title">Passport</h2><span className="mono text-faint">lp:{shortId(a.id)}</span></div>
            {body ? (
              <dl className="p-4 text-sm grid grid-cols-[96px_1fr] gap-y-2.5 gap-x-3">
                <dt className="text-mute">Source</dt><dd className="break-words">{body.source.hub ?? "local"}{body.source.repo ? ` / ${body.source.repo}` : ""}</dd>
                <dt className="text-mute">Commit</dt><dd className="mono truncate">{body.source.commit?.slice(0, 12) ?? "n/a"}</dd>
                <dt className="text-mute">Issued by</dt><dd>{body.issued_by.name}</dd>
                <dt className="text-mute">Issued</dt><dd>{dt(body.issued_at)}</dd>
                <dt className="text-mute">Expires</dt><dd>{body.expires_at ? dt(body.expires_at) : "Never"}</dd>
                <dt className="text-mute">Merkle root</dt><dd className="mono break-all">{body.contents.merkle_root.slice(0, 24)}…</dd>
                <dt className="text-mute">Parents</dt>
                <dd>{body.parents.length ? body.parents.map((p) => <Link key={p} className="mono text-accent hover:underline block" to={`/artifacts/${encodeURIComponent(p)}`}>lp:{shortId(p)}</Link>) : <span className="text-faint">None (root)</span>}</dd>
                <dt className="text-mute">Signature</dt><dd className="mono truncate">{passport!.key_id}</dd>
              </dl>) : <Empty title="No passport" hint="This artifact arrived without provenance." />}
            <div className="px-4 pb-4"><button className="btn w-full" onClick={runVerify}>Verify passport</button>
              {verify && <p className="text-xs mt-2 text-mute" role="status">{verify}</p>}</div>
          </section>
          <section className="card">
            <div className="card-h"><h2 className="h-title">Compliance</h2></div>
            <div className="p-4 flex flex-wrap gap-2">
              {controls.length ? controls.map((c) => <span key={c} className="mono border border-line rounded px-2 py-1 bg-raised">{c}</span>)
                : <p className="text-sm text-faint">No findings map to a control. Controls shown here come from the policy's compliance map.</p>}
            </div>
          </section>
        </aside>
      </div>
    </div>
  );
}
