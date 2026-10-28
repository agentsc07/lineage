import { useState } from "react";
import { Bar, BarChart, CartesianGrid, Legend, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { useAsync } from "../lib/useAsync";
import { loadBench } from "../lib/bench";
import { ErrorBox, Header, Kpi, Loading } from "../components/ui";

const pct = (n: number | null) => (n === null ? "not measured" : `${Math.round(n * 1000) / 10}%`);
const sec = (n: number | null) => (n === null ? "not measured" : `${n.toFixed(1)} s`);
const dec = (n: number | null, d = 3) => (n === null ? "not measured" : n.toFixed(d));
const css = (v: string) => `rgb(var(--${v}))`;
const tip = { contentStyle: { background: css("panel"), border: `1px solid ${css("line")}`, borderRadius: 8, fontSize: 12, color: css("ink") }, cursor: { fill: css("raised") } };
const axis = { stroke: css("faint"), fontSize: 12, tickLine: false } as const;

// bench/results_final.json: the frozen three-tier evaluation (in-sample, tuned-on, final held-out). See docs/CLAIMS.md.
const TIERS: { key: string; title: string; note: string }[] = [
  { key: "in-sample (bench/corpus)", title: "In-sample", note: "the set the rules were built against: measures fit, not generalisation" },
  { key: "dev (tuned on)", title: "Tuned-on sets", note: "rules were tuned on these after the first runs" },
  { key: "FINAL unseen", title: "Final held-out", note: "built after the code was frozen, run once: the only unseen result" },
];
const frac = (a?: number, b?: number) => (a == null || !b ? "not measured" : `${Math.round((1000 * a) / b) / 10}% (${a}/${b})`);

function Tiers() {
  const { data } = useAsync(() => fetch("/bench-data/results_final.json").then((r) => (r.ok ? r.json() : null)).catch(() => null), []);
  const cols = data?.columns;
  if (!cols) return null;
  return (
    <section className="card mb-4">
      <div className="card-h flex-col !items-start !gap-0"><h2 className="h-title">Three evaluation tiers (frozen run)</h2>
        <p className="text-xs text-faint">Full system on our own inert samples; real PyPI packages are presumed benign. Intakes that timed out count as not flagged. Source: bench/results_final.json; read docs/CLAIMS.md before quoting.</p></div>
      <div className="grid md:grid-cols-3 gap-4 p-4">
        {TIERS.map((t) => { const c = cols[t.key]; if (!c) return null; const s = c.synthetic_full, py = c.pypi; return (
          <div key={t.key} className="border border-line rounded-lg p-3">
            <p className="font-medium">{t.title}</p><p className="text-xs text-faint mb-2">{t.note}</p>
            <dl className="grid grid-cols-[1fr_auto] gap-y-1 text-sm">
              <dt className="text-mute">Attacks caught</dt><dd className="mono">{frac(s?.tp, s?.n_mal)}</dd>
              <dt className="text-mute">Benign stopped</dt><dd className="mono">{frac(s?.fp, s?.n_ben)}</dd>
              <dt className="text-mute">Real packages flagged</dt><dd className="mono">{py?.n ? `${frac(py.flagged, py.n)}${py.timeouts ? ` · ${py.timeouts} timed out` : ""}` : "none in this tier"}</dd>
            </dl>
          </div>); })}
      </div>
    </section>
  );
}

export default function Bench() {
  const { data, error, reload } = useAsync(loadBench);
  const [mode, setMode] = useState<string | null>(null);
  if (error) return <div className="page"><ErrorBox msg={error} retry={reload} /></div>;
  if (!data) return <div className="page"><Loading /></div>;

  // Default to the most capable run (the last one listed: deep stages on, with the GPU worker).
  const m = data.modes.find((x) => x.name === mode) ?? data.modes[data.modes.length - 1];
  const cats = (m?.categories ?? []).map((c) => ({ ...c, rate: c.malicious ? c.detected / c.malicious : 0 }));
  const { weight: w, reviewer: rv } = data;
  const ci = w?.ci ? `95% CI ${w.ci[0].toFixed(2)} to ${w.ci[1].toFixed(2)}` : "CI not measured";

  return (
    <div className="page">
      <Header title="Bench" sub="LineageBench: labelled attacks and benign controls. Every number comes from bench/*.json; anything not yet measured says so."
        actions={data.modes.length > 1 ? (
          <select className="input !w-72" aria-label="Bench run" value={m?.name} onChange={(e) => setMode(e.target.value)}>
            {data.modes.map((x) => <option key={x.name} value={x.name}>{x.name}</option>)}</select>) : undefined} />

      <Tiers />
      <p className="text-xs text-faint mb-2">Below: the in-sample LineageBench run, by category (built against this set).</p>
      <div className="grid grid-cols-2 xl:grid-cols-4 gap-4 mb-4">
        <Kpi label="Detection, in-sample (attacks caught)" value={pct(m?.tpr ?? null)} sub={m ? `${m.malicious} labelled attacks · ${data.items ?? "?"} items in the corpus` : "not measured"} />
        <Kpi label="False positives, in-sample" value={pct(m?.fpr ?? null)} sub={m ? `of ${m.benign} benign artifacts wrongly stopped` : undefined} />
        <Kpi label="Weight-space AUROC" value={dec(w?.auroc ?? null, 2)} sub={w ? `${ci} · ${w.nTest ?? "?"} held-out adapters` : undefined} />
        <div title={data.cost?.formula ?? "not measured: bench/cost_log.csv missing"}>
          <Kpi label="GPU cost per artifact ⓘ" value={data.cost?.usdPerArtifact == null ? "not measured" : `$${data.cost.usdPerArtifact.toFixed(3)}`}
            sub={data.cost ? `${data.cost.gpuHours} GPU h logged × $1.74/h (L40S) ÷ ${data.cost.items ?? "?"} artifacts. Hover for the formula.` : undefined} />
        </div>
      </div>

      <div className="grid xl:grid-cols-2 gap-4">
        <section className="card">
          <div className="card-h flex-col !items-start !gap-0"><h2 className="h-title">Detection and false positives by category</h2><p className="text-xs text-faint">Attacks caught of those labelled malicious; benign artifacts wrongly stopped</p></div>
          {cats.length === 0 ? <p className="p-4 text-sm text-mute">not measured</p> : (
            <table className="w-full"><thead><tr><th className="th">Category</th><th className="th">Caught</th><th className="th w-1/3">Detection</th><th className="th">False positives</th></tr></thead>
              <tbody>{cats.map((c) => (
                <tr key={c.key} className="hover:bg-raised/50">
                  <td className="td font-medium">{c.label}{c.auroc !== null && <span className="text-xs text-faint ml-2">AUROC {c.auroc.toFixed(2)}</span>}</td>
                  <td className="td tabular-nums whitespace-nowrap">{c.detected} of {c.malicious}</td>
                  <td className="td"><div className="flex items-center gap-2"><div className="h-2 flex-1 rounded bg-raised overflow-hidden"><div className="h-full" style={{ width: `${c.rate * 100}%`, background: css(c.rate >= 0.9 ? "allow" : c.rate >= 0.6 ? "cond" : "block") }} /></div><span className="text-xs tabular-nums w-10 text-right">{pct(c.rate)}</span></div></td>
                  <td className="td tabular-nums whitespace-nowrap" style={c.fp ? { color: css("quar") } : undefined}>{c.fp} of {c.benign}</td>
                </tr>))}</tbody></table>)}
        </section>

        <div className="flex flex-col gap-4">
          <section className="card">
            <div className="card-h flex-col !items-start !gap-0"><h2 className="h-title">Weight-space backdoor detector</h2><p className="text-xs text-faint">Logistic model on LoRA spectral features, held-out test split</p></div>
            {!w ? <p className="p-4 text-sm text-mute">not measured</p> : (
              <dl className="grid grid-cols-2 md:grid-cols-4 gap-4 p-4 text-sm">
                <Stat k="AUROC (test)" v={dec(w.auroc, 3)} /><Stat k="95% CI" v={w.ci ? `${w.ci[0].toFixed(2)} to ${w.ci[1].toFixed(2)}` : "not measured"} />
                <Stat k="5-fold CV mean" v={dec(w.cv5, 3)} /><Stat k="Adapters" v={w.nAdapters === null ? "not measured" : String(w.nAdapters)} />
              </dl>)}
          </section>
          <section className="card">
            <div className="card-h flex-col !items-start !gap-0"><h2 className="h-title">LLM reviewer</h2><p className="text-xs text-faint">Nemotron reviewer on a small, partly tuned set of labelled code, cards and templates (bench/reviewer.json); can only raise risk</p></div>
            {!rv ? <p className="p-4 text-sm text-mute">not measured: bench/reviewer.json is missing.</p> : (
              <>
                <dl className="grid grid-cols-2 md:grid-cols-3 gap-4 p-4 text-sm">
                  <Stat k="Precision" v={pct(rv.precision)} /><Stat k="Recall" v={pct(rv.recall)} />
                  <Stat k="False positives" v={pct(rv.fpr)} />
                  <Stat k="Latency p50" v={sec(rv.p50S)} /><Stat k="Latency p95" v={sec(rv.p95S)} />
                  <Stat k="Tokens / second" v={rv.tokensPerS === null ? "not measured" : rv.tokensPerS.toFixed(1)} />
                </dl>
                <p className="px-4 pb-3 text-xs text-faint" title={rv.costUsd === null ? undefined : `${rv.wallS} s of GPU wall time ÷ 3600 × $1.74/h (L40S) ÷ ${rv.items} items`}>
                  {rv.llm ?? "reviewer model not recorded"} · {rv.items ?? "?"} items · reviewer GPU cost per artifact {rv.costUsd === null ? "not measured" : `$${rv.costUsd.toFixed(4)}`} ⓘ
                </p>
              </>)}
          </section>
        </div>

        <div className="xl:col-span-2">
          <section className="card">
            <div className="card-h flex-col !items-start !gap-0"><h2 className="h-title">Time per check</h2><p className="text-xs text-faint">Median and 95th percentile in milliseconds, per check type</p></div>
            <div className="p-3" style={{ height: 280 }}>
              {!m || m.latency.length === 0 ? <p className="p-1 text-sm text-mute">not measured</p> : (
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={m.latency} margin={{ right: 16 }}>
                    <CartesianGrid vertical={false} stroke={css("line")} />
                    <XAxis dataKey="check" {...axis} /><YAxis {...axis} />
                    <Tooltip {...tip} formatter={(v: number) => `${v} ms`} /><Legend wrapperStyle={{ fontSize: 12 }} />
                    <Bar dataKey="p50_ms" name="Median" fill={css("accent")} radius={[4, 4, 0, 0]} />
                    <Bar dataKey="p95_ms" name="95th percentile" fill={css("faint")} radius={[4, 4, 0, 0]} />
                  </BarChart>
                </ResponsiveContainer>)}
            </div>
          </section>
        </div>
      </div>
    </div>
  );
}

function Stat({ k, v }: { k: string; v: string }) {
  return <div><dt className="text-mute text-xs">{k}</dt><dd className="text-lg font-semibold tabular-nums mt-0.5">{v}</dd></div>;
}
