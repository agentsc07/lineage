import { useEffect, useMemo, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { Background, Controls, Handle, Position, ReactFlow, type Edge, type Node, type NodeProps } from "@xyflow/react";
import { api } from "../lib/api";
import { useAsync } from "../lib/useAsync";
import { trustColor, trustOrder, verdictKey, type VerdictKey } from "../lib/format";
import { useMonitorIds } from "../lib/monitor";
import type { GraphEdge, GraphNode, RevokeResult } from "../lib/types";
import { ErrorBox, Header, Loading, Trust, Verdict } from "../components/ui";

type NData = { node: GraphNode; state: "idle" | "revoked" | "hit"; vkey: VerdictKey | null } & Record<string, unknown>;

// Border colour follows the decision; the trust ladder stays as the bar inside the node.
const decisionColor: Record<VerdictKey, string> = {
  allow: "var(--allow)", allow_with_conditions: "var(--cond)", quarantine: "var(--quar)", block: "var(--block)", block_monitor: "var(--block)", revoked: "var(--block)",
};

function LineageNode({ data, selected }: NodeProps<Node<NData>>) {
  const { node, state } = data;
  const vkey: VerdictKey | null = state === "revoked" ? "revoked" : data.vkey;
  const hit = state === "hit";
  const color = hit ? "var(--block)" : vkey ? decisionColor[vkey] : "var(--faint)";
  const ghost = node.status === "unregistered"; // referenced but never admitted: drawn dashed
  const group = !!node.group_members?.length, advised = !!node.advisories?.length;
  const dashed = vkey === "revoked" || hit || ghost;
  return (
    <div className={`rounded-lg border bg-panel px-3 py-2 min-w-[200px] transition-colors ${hit ? "blast" : ""} ${selected ? "ring-2 ring-accent" : ""}`}
      style={{ borderColor: `rgb(${color})`, borderLeftWidth: 4, borderStyle: dashed ? "dashed" : "solid", background: dashed ? "rgb(var(--block) / .07)" : undefined }}>
      <Handle type="target" position={Position.Left} className="!bg-faint !border-0 !w-1.5 !h-1.5" />
      <div className="flex items-center justify-between gap-3">
        <span className={`text-sm font-medium truncate ${vkey === "revoked" ? "line-through decoration-block/60" : ""}`}>{node.label}</span>
        <span className="text-xs text-mute capitalize">{node.artifact_type}</span>
      </div>
      <div className="mt-1.5 flex items-center justify-between gap-2">
        <Trust level={node.trust_level} label={false} />
        {hit ? <span className="text-xs font-medium text-block border border-dashed border-block/40 rounded-md px-2 py-0.5">Affected</span> : advised ? <span className="text-xs font-medium text-quar border border-dashed border-quar/50 rounded-md px-2 py-0.5">Advisory</span> : group ? <span className="text-xs text-mute border border-dashed border-faint rounded-md px-2 py-0.5">Click to expand</span> : ghost ? <span className="text-xs text-mute border border-dashed border-faint rounded-md px-2 py-0.5">Not admitted</span> : <Verdict outcome={vkey} />}
      </div>
      <Handle type="source" position={Position.Right} className="!bg-faint !border-0 !w-1.5 !h-1.5" />
    </div>
  );
}
const nodeTypes = { lineage: LineageNode };

export default function GraphPage() {
  const { id } = useParams();
  const nav = useNavigate();
  const monitorIds = useMonitorIds();
  const arts = useAsync(api.artifacts);
  // Default to the artifact whose chain (ancestors + descendants) is largest, so the full story shows on load.
  const biggest = useAsync(async () => {
    const list = arts.data ?? [];
    const sizes = await Promise.all(list.slice(0, 40).map(async (a) => {
      const [up, down] = await Promise.all([api.graph(a.id, "up"), api.graph(a.id, "down")]);
      return { id: a.id, size: new Set([...up.nodes, ...down.nodes].map((n) => n.id)).size };
    }));
    return sizes.reduce<{ id: string; size: number } | null>((b, c) => (!b || c.size > b.size ? c : b), null)?.id ?? null;
  }, [arts.data]);
  const rootId = id ?? biggest.data ?? undefined;
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
  const [selEdge, setSelEdge] = useState<GraphEdge | null>(null);
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => { setResult(null); setWave(new Set()); setSel(null); setSelEdge(null); setExpanded(new Set()); }, [rootId]);
  const target = sel ?? rootId;

  // An expanded group is replaced by its members (they came in the payload; nothing more is fetched).
  const shown = useMemo(() => {
    const g = graph.data;
    if (!g) return null;
    const open = g.nodes.filter((n) => n.group_members?.length && expanded.has(n.id));
    if (!open.length) return g;
    const gone = new Set(open.map((n) => n.id));
    const nodes = [...g.nodes.filter((n) => !gone.has(n.id)), ...open.flatMap((n) => n.group_members!)];
    const edges: GraphEdge[] = [...g.edges.filter((e) => !gone.has(e.source)), ...open.flatMap((n) => {
      const child = g.edges.find((e) => e.source === n.id)!.target;
      return n.group_members!.map((m) => ({ source: m.id, target: child, kind: "built_with", evidence: "sbom" }));
    })];
    return { nodes, edges };
  }, [graph.data, expanded]);

  const { nodes, edges } = useMemo(() => {
    const g = shown;
    if (!g) return { nodes: [] as Node<NData>[], edges: [] as Edge[] };
    // Lay out by depth (longest path from a root), left to right.
    const depth = new Map<string, number>();
    const parents = (n: string) => g.edges.filter((e) => e.target === n).map((e) => e.source);
    const d = (n: string): number => { if (depth.has(n)) return depth.get(n)!; const p = parents(n); const v = p.length ? 1 + Math.max(...p.map(d)) : 0; depth.set(n, v); return v; };
    const perCol = new Map<number, number>();
    const ns: Node<NData>[] = g.nodes.map((n) => {
      const col = d(n.id); const row = perCol.get(col) ?? 0; perCol.set(col, row + 1);
      const state = result?.revoked === n.id ? "revoked" : wave.has(n.id) ? "hit" : "idle";
      return { id: n.id, type: "lineage", position: { x: col * 280, y: row * 110 }, data: { node: n, state, vkey: verdictKey(n.status, null, n.id, monitorIds) }, selected: n.id === target };
    });
    const es: Edge[] = g.edges.map((e) => {
      const hot = (result?.revoked === e.source || wave.has(e.source)) && wave.has(e.target);
      return { id: e.source + "->" + e.target, source: e.source, target: e.target, animated: hot, label: e.evidence || undefined, labelStyle: { fontSize: 10, fill: "rgb(var(--faint))" }, interactionWidth: 18,
        style: { stroke: hot ? "rgb(var(--block))" : "rgb(var(--faint))", strokeWidth: hot ? 2.5 : 1.5 } };
    });
    return { nodes: ns, edges: es };
  }, [shown, result, wave, target, monitorIds]);

  const revoke = async () => {
    if (!target) return;
    setBusy(true); setErr(null); setWave(new Set());
    try {
      const r = await api.revoke(target, "Revoked from the dashboard");
      setResult(r);
      // Spread the blast radius outward one generation at a time.
      const g = shown!; let frontier = [r.revoked]; const hit = new Set(r.blast_radius.map((n) => n.id)); const seen = new Set<string>();
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
  const sn = shown?.nodes.find((n) => n.id === target);
  const registered = (shown?.nodes ?? []).filter((n) => n.status !== "unregistered").map((n) => ({ id: n.id }));

  return (
    <div className="page">
      <Header title="Lineage" sub="How artifacts derive from one another. Revoking an artifact flags everything built on it."
        actions={<>
          <select className="input !w-56" aria-label="Artifact" value={rootId ?? ""} onChange={(e) => nav(`/graph/${encodeURIComponent(e.target.value)}`)}>
            {arts.data.map((a) => <option key={a.id} value={a.id}>{a.name}@{a.version}</option>)}</select>
          <button className="btn btn-danger" onClick={revoke} disabled={busy || !target || !!result || sn?.id.startsWith("sbom-group:")}>{busy ? "Tracing…" : `Revoke ${sn?.label ?? ""}`}</button>
        </>} />
      {err && <p className="text-block text-sm mb-3">{err}</p>}
      <p className="text-xs text-faint mb-2" data-testid="graph-notice">This graph contains only what passed through Lineage or was recorded by <span className="mono">lineage run</span>.</p>
      <div className="card h-[max(520px,calc(100vh-190px))] relative overflow-hidden">
        <ReactFlow nodes={nodes} edges={edges} nodeTypes={nodeTypes} fitView fitViewOptions={{ padding: 0.3, nodes: registered.length ? registered : undefined }} nodesDraggable={false}
          onNodeClick={(_, n) => { setSel(n.id); setSelEdge(null); const gn = shown?.nodes.find((x) => x.id === n.id); if (gn?.group_members?.length) setExpanded((x) => new Set(x).add(n.id)); }}
          onEdgeClick={(_, e) => { const ge = shown?.edges.find((x) => x.source + "->" + x.target === e.id); if (ge) setSelEdge(ge); }} proOptions={{ hideAttribution: true }} colorMode={document.documentElement.dataset.theme === "light" ? "light" : "dark"}>
          <Background gap={20} color="rgb(var(--line))" /><Controls showInteractive={false} />
        </ReactFlow>
        <div className="absolute left-3 bottom-3 card px-3 py-2 flex gap-3 text-xs text-mute">
          <span className="text-faint">Trust</span>
          {trustOrder.map((t) => <span key={t} className="flex items-center gap-1.5 capitalize"><span className="w-2 h-2 rounded-sm" style={{ background: `rgb(${trustColor[t]})` }} />{t}</span>)}
          <span className="text-faint ml-2">Border</span>
          {([["allow", "Allow"], ["quarantine", "Quarantine"], ["block", "Block"]] as const).map(([k, l]) => <span key={k} className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-sm" style={{ background: `rgb(${decisionColor[k]})` }} />{l}</span>)}
          <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-sm border border-dashed border-block" />Revoked</span>
        </div>
      </div>
      {(selEdge || (sn && sn.status === "unregistered")) && <Detail node={sn} edge={selEdge} nodes={shown?.nodes ?? []} />}
      {result && (
        <section className="card mt-4 p-4 border-block/40" role="status">
          <p className="font-medium text-block">{result.revoked === target && sn ? sn.label : "Artifact"} revoked</p>
          <p className="text-sm text-mute mt-1">{result.blast_radius.length === 0 ? "Nothing else depends on it." : `${result.blast_radius.length} downstream artifact${result.blast_radius.length === 1 ? "" : "s"} now need review:`}</p>
          <ul className="mt-2 flex flex-wrap gap-2">{result.blast_radius.map((n) => <li key={n.id} className="text-sm border border-block/40 bg-block/10 text-block rounded px-2 py-1">{n.label} <span className="text-xs opacity-70">{n.artifact_type}</span></li>)}</ul>
        </section>)}
    </div>
  );
}

const EVIDENCE: Record<string, string> = {
  fetched: "read from what the hub or the package index published (trusted)",
  signed: "stated in a creator passport whose key the policy trusts for this source",
  recorded: "recorded by `lineage run` in a verified passport (inputs it saw)",
  declared: "named by the uploader; not verified",
  "inferred-from-weights": "matched from the weights, not claimed by anyone",
  sbom: "the training environment's package list, recorded by `lineage run`; the packages were never admitted",
};

/** Built from the graph payload only: no request is made for a ghost or a group. */
function Detail({ node, edge, nodes }: { node?: GraphNode; edge: GraphEdge | null; nodes: GraphNode[] }) {
  const label = (id: string) => nodes.find((n) => n.id === id)?.label ?? id;
  return (
    <section className="card mt-4 p-4 text-sm" aria-label="Graph detail" data-testid="graph-detail">
      {edge ? (
        <>
          <p className="font-medium">Edge: {label(edge.source)} → {label(edge.target)}</p>
          <p className="text-mute mt-1">Kind <span className="mono">{edge.kind}</span> · evidence <span className="mono">{edge.evidence || "unknown"}</span></p>
          <p className="text-xs text-faint mt-1">{EVIDENCE[edge.evidence ?? ""] ?? "no evidence class recorded"}</p>
        </>
      ) : node ? (
        <>
          <p className="font-medium">{node.group_members?.length ? node.label : `${node.label}${node.version ? "" : ""}`}</p>
          <dl className="grid grid-cols-[120px_1fr] gap-y-1 mt-2 text-mute">
            <dt>Name / version</dt><dd className="mono">{node.group_members?.length ? `${node.group_members.length} packages` : `${node.label}${node.version ? ` (version ${node.version})` : ""}`}</dd>
            <dt>Status</dt><dd>referenced, never admitted by Lineage</dd>
            <dt>Origin</dt><dd>recorded from the training SBOM by <span className="mono">lineage run</span>; never admitted</dd>
            <dt>Advisories</dt><dd>{node.advisories?.length ? <span className="text-quar">{node.advisories.join(", ")}</span> : "none seen by the monitor"}</dd>
          </dl>
        </>
      ) : null}
    </section>
  );
}
