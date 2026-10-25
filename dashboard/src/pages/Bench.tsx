import { Bar, BarChart, CartesianGrid, Cell, Legend, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { useAsync } from "../lib/useAsync";
import { ErrorBox, Header, Kpi, Loading } from "../components/ui";

interface Results {
  sample?: boolean; note?: string; generated: string;
  summary: { precision: number; recall: number; f1: number; fpr: number };
  by_category: { category: string; detected: number; total: number }[];
  baselines: { name: string; recall: number; fpr: number }[];
  latency: { stage: string; p50_ms: number; p95_ms: number }[];
  cost: { gpu_seconds_per_artifact: number; usd_per_1000_artifacts: number };
}
const pct = (n: number) => `${Math.round(n * 100)}%`;
const css = (v: string) => `rgb(var(--${v}))`;
const tip = { contentStyle: { background: css("panel"), border: `1px solid ${css("line")}`, borderRadius: 8, fontSize: 12, color: css("ink") }, cursor: { fill: css("raised") } };
const axis = { stroke: css("faint"), fontSize: 12, tickLine: false } as const;

export default function Bench() {
  // Prefer the real results served from /bench-results.json; the repo ships a labelled sample.
  const { data, error, reload } = useAsync<Results>(() => fetch("/bench-results.json").then((r) => { if (!r.ok) throw new Error("bench-results.json not found"); return r.json(); }));
  if (error) return <div className="page"><ErrorBox msg={error} retry={reload} /></div>;
  if (!data) return <div className="page"><Loading /></div>;
  const cat = data.by_category.map((c) => ({ ...c, rate: c.detected / c.total }));

  return (
    <div className="page">
      <Header title="Bench" sub="LineageBench: labelled attacks and benign controls, scored against simpler baselines." />
      {data.sample && <p className="card border-cond/40 text-cond text-sm px-4 py-2.5 mb-4">Sample data. {data.note}</p>}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-4">
        <Kpi label="Recall" value={pct(data.summary.recall)} sub="Attacks caught" />
        <Kpi label="Precision" value={pct(data.summary.precision)} sub="Blocks that were real attacks" />
        <Kpi label="False positives" value={pct(data.summary.fpr)} sub="Benign artifacts wrongly stopped" />
        <Kpi label="Cost" value={`$${data.cost.usd_per_1000_artifacts.toFixed(2)}`} sub={`per 1,000 artifacts · ${data.cost.gpu_seconds_per_artifact}s GPU each`} />
      </div>
      <div className="grid lg:grid-cols-2 gap-4">
        <Chart title="Detection by attack category" note="Share of labelled attacks caught">
          <BarChart data={cat} layout="vertical" margin={{ left: 24, right: 16 }}>
            <CartesianGrid horizontal={false} stroke={css("line")} />
            <XAxis type="number" domain={[0, 1]} tickFormatter={pct} {...axis} />
            <YAxis type="category" dataKey="category" width={150} {...axis} />
            <Tooltip {...tip} formatter={(v: number, _n, p) => [`${p.payload.detected} of ${p.payload.total} (${pct(v)})`, "Caught"]} />
            <Bar dataKey="rate" radius={[0, 4, 4, 0]}>{cat.map((c) => <Cell key={c.category} fill={css(c.rate >= 0.9 ? "allow" : c.rate >= 0.75 ? "cond" : "quar")} />)}</Bar>
          </BarChart>
        </Chart>
        <Chart title="Lineage against baselines" note="Higher recall and lower false positives are better">
          <BarChart data={data.baselines} margin={{ right: 16 }}>
            <CartesianGrid vertical={false} stroke={css("line")} />
            <XAxis dataKey="name" {...axis} interval={0} tick={{ fontSize: 11, fill: css("mute") }} />
            <YAxis tickFormatter={pct} domain={[0, 1]} {...axis} />
            <Tooltip {...tip} formatter={(v: number) => pct(v)} />
            <Legend wrapperStyle={{ fontSize: 12 }} />
            <Bar dataKey="recall" name="Recall" fill={css("accent")} radius={[4, 4, 0, 0]} />
            <Bar dataKey="fpr" name="False positive rate" fill={css("block")} radius={[4, 4, 0, 0]} />
          </BarChart>
        </Chart>
        <div className="lg:col-span-2">
          <Chart title="Time per stage" note="Median and 95th percentile, milliseconds" h={260}>
            <BarChart data={data.latency} margin={{ right: 16 }}>
              <CartesianGrid vertical={false} stroke={css("line")} />
              <XAxis dataKey="stage" {...axis} /><YAxis {...axis} />
              <Tooltip {...tip} formatter={(v: number) => `${v} ms`} /><Legend wrapperStyle={{ fontSize: 12 }} />
              <Bar dataKey="p50_ms" name="Median" fill={css("accent")} radius={[4, 4, 0, 0]} />
              <Bar dataKey="p95_ms" name="95th percentile" fill={css("faint")} radius={[4, 4, 0, 0]} />
            </BarChart>
          </Chart>
        </div>
      </div>
    </div>
  );
}

function Chart({ title, note, children, h = 300 }: { title: string; note: string; children: React.ReactElement; h?: number }) {
  return (
    <section className="card">
      <div className="card-h flex-col !items-start !gap-0"><h2 className="h-title">{title}</h2><p className="text-xs text-faint">{note}</p></div>
      <div className="p-3" style={{ height: h }}><ResponsiveContainer width="100%" height="100%">{children}</ResponsiveContainer></div>
    </section>
  );
}
