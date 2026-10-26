// Adapter from bench/results.json, weightspace.json and reviewer.json to what the Bench page shows.
// Any number the files do not contain is null and rendered as "not measured"; nothing is estimated.

export interface Category { key: string; label: string; detected: number; malicious: number; fp: number; benign: number; auroc: number | null }
export interface ModeView {
  name: string; tpr: number | null; fpr: number | null; malicious: number; benign: number;
  categories: Category[]; latency: { check: string; n: number; p50_ms: number | null; p95_ms: number | null }[];
}
export interface WeightSpace { auroc: number | null; ci: [number, number] | null; nTest: number | null; nAdapters: number | null; cv5: number | null }
export interface Reviewer {
  llm: string | null; items: number | null; precision: number | null; recall: number | null; fpr: number | null;
  p50S: number | null; p95S: number | null; tokensPerS: number | null; promptTokens: number | null; completionTokens: number | null;
  wallS: number | null; costUsd: number | null;
}
export const L40S_USD_PER_HOUR = 1.74;
export interface Cost { gpuHours: number; jobs: number; usd: number; items: number | null; usdPerArtifact: number | null; formula: string }
export interface BenchView { generated: string | null; items: number | null; modes: ModeView[]; weight: WeightSpace | null; reviewer: Reviewer | null; gpuHours: number | null; cost: Cost | null }

const num = (v: unknown): number | null => (typeof v === "number" && Number.isFinite(v) ? v : null);
const pick = (o: any, ...keys: string[]): number | null => { for (const k of keys) { const n = num(o?.[k]); if (n !== null) return n; } return null; };
const label = (k: string) => k.replace(/_/g, " ").replace(/^./, (c) => c.toUpperCase()).replace(/\b(mcp|lora)\b/gi, (w) => (w.toLowerCase() === "mcp" ? "MCP" : "LoRA"));
const ms = (s: unknown) => (num(s) === null ? null : Math.round((s as number) * 1000 * 10) / 10);

async function load(name: string): Promise<any | null> {
  try {
    const r = await fetch(`/bench-data/${name}`);
    if (!r.ok || !(r.headers.get("content-type") ?? "").includes("json")) return null;
    return await r.json();
  } catch { return null; }
}

async function loadText(name: string): Promise<string | null> {
  try {
    const r = await fetch(`/bench-data/${name}`);
    if (!r.ok || !(r.headers.get("content-type") ?? "").includes("csv")) return null;
    return await r.text();
  } catch { return null; }
}

export function adaptResults(r: any): Pick<BenchView, "generated" | "items" | "modes" | "gpuHours"> {
  const modes: ModeView[] = Object.entries(r?.modes ?? {}).map(([name, m]: [string, any]) => ({
    name,
    tpr: num(m.overall?.tpr), fpr: num(m.overall?.fpr), malicious: m.overall?.n_malicious ?? 0, benign: m.overall?.n_benign ?? 0,
    categories: Object.entries(m.categories ?? {}).map(([key, c]: [string, any]) => ({
      key, label: label(key), detected: c.tp ?? 0, malicious: c.n_malicious ?? 0, fp: c.fp ?? 0, benign: c.n_benign ?? 0, auroc: num(c.auroc),
    })),
    latency: Object.entries(m.latency ?? {}).map(([check, l]: [string, any]) => ({ check: label(check), n: l.n ?? 0, p50_ms: ms(l.p50_s), p95_ms: ms(l.p95_s) })),
  }));
  return { generated: r?.generated ?? null, items: num(r?.corpus_items), modes, gpuHours: num(r?.cost?.gpu_hours_logged_total) };
}

export function adaptWeightspace(w: any): WeightSpace | null {
  if (!w) return null;
  const ci = Array.isArray(w.test?.ci95) && w.test.ci95.length === 2 ? ([w.test.ci95[0], w.test.ci95[1]] as [number, number]) : null;
  return { auroc: num(w.test?.auroc), ci, nTest: num(w.n_test), nAdapters: num(w.n_adapters), cv5: num(w.auroc_cv5_mean) };
}

export function adaptReviewer(v: any): Reviewer | null {
  if (!v?.overall) return null;
  const o = v.overall, lat = v.latency?.request_wall_s, tok = v.tokens;
  const n = num(v.n_items);
  const wallS = num(v.total_wall_s);
  return {
    llm: v.reviewer_llm ?? null, items: n, precision: num(o.precision), recall: num(o.recall), fpr: num(o.false_positive_rate),
    p50S: num(lat?.p50), p95S: num(lat?.p95), tokensPerS: num(tok?.generation_tokens_per_s_incl_prefill),
    promptTokens: num(tok?.prompt), completionTokens: num(tok?.completion), wallS,
    // GPU busy for the whole bench run, split over the items it reviewed.
    costUsd: wallS !== null && n ? (wallS / 3600) * L40S_USD_PER_HOUR / n : null,
  };
}

// cost_log.csv: one row per GPU job with gpu_hours. Amortise all logged GPU time over the corpus items.
export function adaptCost(csv: string | null, items: number | null): Cost | null {
  if (!csv) return null;
  const [head, ...rows] = csv.trim().split(/\r?\n/).map((l) => l.split(","));
  const col = head?.indexOf("gpu_hours");
  if (col === undefined || col < 0) return null;
  const hours = rows.map((r) => Number(r[col])).filter((h) => Number.isFinite(h));
  if (!hours.length) return null;
  const gpuHours = Math.round(hours.reduce((a, b) => a + b, 0) * 1000) / 1000;
  const usd = gpuHours * L40S_USD_PER_HOUR;
  const per = items ? usd / items : null;
  return { gpuHours, jobs: hours.length, usd, items, usdPerArtifact: per,
    formula: `${gpuHours} GPU h (${hours.length} jobs in bench/cost_log.csv) × $${L40S_USD_PER_HOUR}/h (L40S) = $${usd.toFixed(2)}; ÷ ${items ?? "?"} corpus artifacts = ${per === null ? "not measured" : "$" + per.toFixed(4)} per artifact` };
}

export async function loadBench(): Promise<BenchView> {
  const [r, w, v, csv] = await Promise.all([load("results.json"), load("weightspace.json"), load("reviewer.json"), loadText("cost_log.csv")]);
  if (!r && !w && !v) throw new Error("No bench results found. Run the bench (bench/run_bench.py) to produce bench/results.json.");
  const base = r ? adaptResults(r) : { generated: null, items: null, modes: [], gpuHours: null };
  return { ...base, weight: adaptWeightspace(w), reviewer: adaptReviewer(v), cost: adaptCost(csv, base.items) };
}
