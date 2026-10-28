// The server's catalogue of checks (lineage/catalog.py): what each check is called, what it looks at and how.
import { useEffect, useState } from "react";
import { api } from "./api";

export interface Checker { key: string; name: string; stage: string; types: string[]; detects: string; how: string; reads: string; needs: string; entry: string; prefixes: string[] }
export interface Catalog { checkers: Checker[]; kinds: Record<string, string>; stages: Record<string, string>; not_run: Record<string, string> }

let cache: Catalog | null = null;
let pending: Promise<Catalog | null> | null = null;
const load = () => (pending ??= api.catalog().then((c) => (cache = c)).catch(() => null));

export function useCatalog(): Catalog | null {
  const [c, setC] = useState<Catalog | null>(cache);
  useEffect(() => { if (!cache) load().then(setC); }, []);
  return c;
}

/** The checker that produced a finding: the longest matching id prefix. */
export function checkerFor(cat: Catalog | null, id: string): Checker | null {
  let best: Checker | null = null, len = -1;
  for (const c of cat?.checkers ?? []) for (const p of c.prefixes) if (id.startsWith(p) && p.length > len) { best = c; len = p.length; }
  return best;
}

export function plainName(cat: Catalog | null, id: string): string {
  if (id.startsWith("CHECK.NOT_RUN.")) {
    const n = id.slice("CHECK.NOT_RUN.".length).split(".")[0];
    return `Did not run: ${cat?.not_run[n] ?? n.replace(/_/g, " ").toLowerCase()}`;
  }
  return checkerFor(cat, id)?.name ?? id;
}
