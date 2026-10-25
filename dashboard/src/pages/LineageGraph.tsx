import { useEffect, useMemo, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { Background, Controls, Handle, Position, ReactFlow, type Edge, type Node, type NodeProps } from "@xyflow/react";
import { api } from "../lib/api";
import { useAsync } from "../lib/useAsync";
import { trustColor, trustOrder } from "../lib/format";
import type { GraphNode, RevokeResult } from "../lib/types";
import { ErrorBox, Header, Loading, Trust } from "../components/ui";

type NData = { node: GraphNode; state: "idle" | "revoked" | "hit" } & Record<string, unknown>;

function LineageNode({ data, selected }: NodeProps<Node<NData>>) {
  const { node, state } = data;
  const color = state === "idle" ? trustColor[node.trust_level] : "var(--block)";
  return (
    <div className={`rounded-lg border bg-panel px-3 py-2 min-w-[190px] transition-colors ${state === "hit" ? "blast" : ""} ${selected ? "ring-2 ring-accent" : ""}`}
      style={{ borderColor: `rgb(${color})`, borderLeftWidth: 4, opacity: state === "idle" ? 1 : 0.95 }}>
      <Handle type="target" position={Position.Left} className="!bg-faint !border-0 !w-1.5 !h-1.5" />
      <div className="flex items-center justify-between gap-3">
        <span className="text-sm font-medium truncate">{node.label}</span>
        <span className="text-xs text-mute capitalize">{node.artifact_type}</span>
      </div>
      <div className="mt-1.5 text-xs">
        {state === "revoked" ? <span className="text-block font-medium">Revoked</span>
          : state === "hit" ? <span className="text-block font-medium">Affected</span>
          : <Trust level={node.trust_level} />}
      </div>
      <Handle type="source" position={Position.Right} className="!bg-faint !border-0 !w-1.5 !h-1.5" />
    </div>
  );
}
const nodeTypes = { lineage: LineageNode };

export default function GraphPage() {
  const { id } = useParams();
  const nav = useNavigate();
  const arts = useAsync(api.artifacts);
  const rootId = id ?? arts.data?.[0]?.id;
  // Show the whole chain: ancestors of the leaf plus descendants of the root.
  const graph = useAsync(async () => {
    if (!rootId) return null;
    const [up, down] = await Promise.all([api.graph(rootId, "up"), api.graph(rootId, "down")]);
    const nodes = new Map([...up.nodes, ...down.nodes].map((n) => [n.id, n]));
    const edges = new Map([...up.edges, ...down.edges].map((e) => [e.source + e.target, e]));
    return { nodes: [...nodes.values()], edges: [...edges.values()] };
  }, [rootId]);
  const [result, setResult] = useState<RevokeResult | null>(null);
  const [wave, setWave] = useState<Set<string>>(new Set());
  const [busy, setBusy] = useState(false);
  const [sel, setSel] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => { setResult(null); setWave(new Set()); setSel(null); }, [rootId]);
  const target = sel ?? rootId;

  const { nodes, edges } = useMemo(() => {
    const g = graph.data;
    if (!g) return { nodes: [] as Node<NData>[], edges: [] as Edge[] };
    // Lay out by depth (longest path from a root), left to right.
    const depth = new Map<string, number>();
    const parents = (n: string) => g.edges.filter((e) => e.target === n).map((e) => e.source);
    const d = (n: string): number => { if (depth.has(n)) return depth.get(n)!; const p = parents(n); const v = p.length ? 1 + Math.max(...p.map(d)) : 0; depth.set(n, v); return v; };
    const perCol = new Map<number, number>();
    const ns: Node<NData>[] = g.nodes.map((n) => {
      const col = d(n.id); const row = perCol.get(col) ?? 0; perCol.set(col, row + 1);
      const state = result?.revoked === n.id ? "revoked" : wave.has(n.id) ? "hit" : "idle";
      return { id: n.id, type: "lineage", position: { x: col * 280, y: row * 110 }, data: { node: n, state }, selected: n.id === target };
    });
    const es: Edge[] = g.edges.map((e) => {
      const hot = (result?.revoked === e.source || wave.has(e.source)) && wave.has(e.target);
      return { id: e.source + e.target, source: e.source, target: e.target, animated: hot,
        style: { stroke: hot ? "rgb(var(--block))" : "rgb(var(--faint))", strokeWidth: hot ? 2.5 : 1.5 } };
    });
    return { nodes: ns, edges: es };
  }, [graph.data, result, wave, target]);

  const revoke = async () => {
    if (!target) return;
    setBusy(true); setErr(null); setWave(new Set());
    try {
      const r = await api.revoke(target, "Revoked from the dashboard");
      setResult(r);
      // Spread the blast radius outward one generation at a time.
      const g = graph.data!; let frontier = [r.revoked]; const hit = new Set(r.blast_radius.map((n) => n.id)); const seen = new Set<string>();
      while (frontier.length) {
        await new Promise((res) => setTimeout(res, 650));
        const next = g.edges.filter((e) => frontier.includes(e.source) && hit.has(e.target) && !seen.has(e.target)).map((e) => e.target);
        next.forEach((n) => seen.add(n)); setWave(new Set(seen)); frontier = next;
      }
      r.blast_radius.forEach((n) => seen.add(n.id)); setWave(new Set(seen));
    } catch (e: any) { setErr(e.message); } finally { setBusy(false); }
  };

  if (arts.error || graph.error) return <div className="page"><ErrorBox msg={arts.error ?? graph.error!} retry={graph.reload} /></div>;
  if (!arts.data) return <div className="page"><Loading /></div>;
  const sn = graph.data?.nodes.find((n) => n.id === target);

  return (
    <div className="page">
      <Header title="Lineage" sub="How artifacts derive from one another. Revoking an artifact flags everything built on it."
        actions={<>
          <select className="input !w-56" aria-label="Artifact" value={rootId} onChange={(e) => nav(`/graph/${encodeURIComponent(e.target.value)}`)}>
            {arts.data.map((a) => <option key={a.id} value={a.id}>{a.name}@{a.version}</option>)}</select>
          <button className="btn btn-danger" onClick={revoke} disabled={busy || !target || !!result}>{busy ? "Tracing…" : `Revoke ${sn?.label ?? ""}`}</button>
        </>} />
      {err && <p className="text-block text-sm mb-3">{err}</p>}
      <div className="card h-[520px] relative overflow-hidden">
        <ReactFlow nodes={nodes} edges={edges} nodeTypes={nodeTypes} fitView fitViewOptions={{ padding: 0.3 }} nodesDraggable={false}
          onNodeClick={(_, n) => setSel(n.id)} proOptions={{ hideAttribution: true }} colorMode={document.documentElement.dataset.theme === "light" ? "light" : "dark"}>
          <Background gap={20} color="rgb(var(--line))" /><Controls showInteractive={false} />
        </ReactFlow>
        <div className="absolute left-3 bottom-3 card px-3 py-2 flex gap-3 text-xs text-mute">
          {trustOrder.map((t) => <span key={t} className="flex items-center gap-1.5 capitalize"><span className="w-2 h-2 rounded-sm" style={{ background: `rgb(${trustColor[t]})` }} />{t}</span>)}
        </div>
      </div>
      {result && (
        <section className="card mt-4 p-4 border-block/40" role="status">
          <p className="font-medium text-block">{result.revoked === target && sn ? sn.label : "Artifact"} revoked</p>
          <p className="text-sm text-mute mt-1">{result.blast_radius.length === 0 ? "Nothing else depends on it." : `${result.blast_radius.length} downstream artifact${result.blast_radius.length === 1 ? "" : "s"} now need review:`}</p>
          <ul className="mt-2 flex flex-wrap gap-2">{result.blast_radius.map((n) => <li key={n.id} className="text-sm border border-block/40 bg-block/10 text-block rounded px-2 py-1">{n.label} <span className="text-xs opacity-70">{n.artifact_type}</span></li>)}</ul>
        </section>)}
    </div>
  );
}
