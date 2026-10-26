// Adapter from bench/results.json, weightspace.json and reviewer.json to what the Bench page shows.
// Any number the files do not contain is null and rendered as "not measured"; nothing is estimated.

export interface Category { key: string; label: string; detected: number; malicious: number; fp: number; benign: number; auroc: number | null }
export interface ModeView {
  name: string; tpr: number | null; fpr: number | null; malicious: number; benign: number;
  categories: Category[]; latency: { check: string; n: number; p50_ms: number | null; p95_ms: number | null }[];
}
export interface WeightSpace { auroc: number | null; ci: [number, number] | null; nTest: number | null; nAdapters: number | null; cv5: number | null }
export interface Reviewer { precision: number | null; recall: number | null; latencyS: number | null; costUsd: number | null }
export interface BenchView { generated: string | null; items: number | null; modes: ModeView[]; weight: WeightSpace | null; reviewer: Reviewer | null; gpuHours: number | null }

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

// reviewer.json is not produced yet; accept the obvious field spellings and show "not measured" for the rest.
export function adaptReviewer(v: any): Reviewer | null {
  if (!v) return null;
  const s = v.summary ?? v;
  return {
    precision: pick(s, "precision"), recall: pick(s, "recall", "tpr"),
    latencyS: pick(s, "latency_s", "p50_s", "mean_latency_s", "seconds_per_artifact"),
    costUsd: pick(s, "cost_usd_per_artifact", "usd_per_artifact", "cost_per_artifact_usd"),
  };
}

export async function loadBench(): Promise<BenchView> {
  const [r, w, v] = await Promise.all([load("results.json"), load("weightspace.json"), load("reviewer.json")]);
  if (!r && !w && !v) throw new Error("No bench results found. Run the bench (bench/run_bench.py) to produce bench/results.json.");
  return { ...(r ? adaptResults(r) : { generated: null, items: null, modes: [], gpuHours: null }), weight: adaptWeightspace(w), reviewer: adaptReviewer(v) };
}
