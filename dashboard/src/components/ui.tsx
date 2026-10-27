import { ReactNode } from "react";
import type { ArtifactStatus, ArtifactType, Outcome, Severity, TrustLevel } from "../lib/types";
import type { VerdictKey } from "../lib/format";
import { extraMeta, outcomeMeta, riskColor, sevMeta, statusOutcome, statusLabel, trustColor, trustOrder } from "../lib/format";

export function Verdict({ outcome, size = "sm" }: { outcome: VerdictKey | null | undefined; size?: "sm" | "lg" }) {
  if (!outcome) return <span className="text-faint text-sm">Pending</span>;
  const m = outcome === "revoked" || outcome === "block_monitor" ? extraMeta[outcome] : outcomeMeta[outcome];
  return (
    <span className={`inline-flex items-center gap-1.5 border rounded-md font-medium whitespace-nowrap ${m.cls} ${size === "lg" ? "px-3 py-1.5 text-base" : "px-2 py-0.5 text-xs"}`}>
      <span className={`rounded-full ${m.dot} ${size === "lg" ? "w-2 h-2" : "w-1.5 h-1.5"}`} />
      {m.label}
    </span>
  );
}

export function StatusPill({ status }: { status: ArtifactStatus }) {
  const o = statusOutcome[status];
  if (!o) return <span className="text-mute text-xs border border-line rounded-md px-2 py-0.5">{statusLabel[status]}</span>;
  const m = outcomeMeta[o];
  return <span className={`text-xs border rounded-md px-2 py-0.5 whitespace-nowrap ${m.cls}`}>{statusLabel[status]}</span>;
}

export function Severity_({ s }: { s: Severity }) {
  return <span className={`text-xs border rounded px-1.5 py-px font-medium ${sevMeta[s].cls}`}>{s}</span>;
}

/** Four-step ladder; filled segments show how far up the trust ladder an artifact is. */
export function Trust({ level, label = true }: { level: TrustLevel; label?: boolean }) {
  const n = trustOrder.indexOf(level) + 1;
  return (
    <span className="inline-flex items-center gap-2">
      <span className="flex gap-0.5" aria-hidden>
        {trustOrder.map((_, i) => (
          <span key={i} className="w-2.5 h-1.5 rounded-sm" style={{ background: i < n ? `rgb(${trustColor[level]})` : "rgb(var(--line))" }} />
        ))}
      </span>
      {label && <span className="text-sm capitalize">{level}</span>}
    </span>
  );
}

export function Risk({ score }: { score: number }) {
  return (
    <span className="inline-flex items-center gap-2 min-w-[84px]">
      <span className="flex-1 h-1.5 rounded bg-line overflow-hidden">
        <span className="block h-full rounded" style={{ width: `${Math.max(score, 3)}%`, background: `rgb(${riskColor(score)})` }} />
      </span>
      <span className="mono w-6 text-right">{score}</span>
    </span>
  );
}

export function TypeTag({ t }: { t: ArtifactType }) {
  return <span className="text-xs text-mute bg-raised border border-line rounded px-1.5 py-px capitalize">{t}</span>;
}

export function Header({ title, sub, actions }: { title: string; sub?: string; actions?: ReactNode }) {
  return (
    <div className="flex items-end justify-between gap-4 mb-6">
      <div>
        <h1 className="text-xl font-semibold tracking-tight">{title}</h1>
        {sub && <p className="text-mute text-sm mt-1 max-w-[62ch]">{sub}</p>}
      </div>
      {actions && <div className="flex gap-2 shrink-0">{actions}</div>}
    </div>
  );
}

export function Empty({ title, hint, children }: { title: string; hint?: string; children?: ReactNode }) {
  return (
    <div className="px-6 py-10 text-center">
      <p className="font-medium">{title}</p>
      {hint && <p className="text-mute text-sm mt-1">{hint}</p>}
      {children && <div className="mt-4 flex justify-center">{children}</div>}
    </div>
  );
}

export function ErrorBox({ msg, retry }: { msg: string; retry?: () => void }) {
  return (
    <div className="card border-block/40 p-4 flex items-center justify-between gap-4">
      <div>
        <p className="font-medium text-block">Can't reach the Lineage server</p>
        <p className="text-mute text-sm mt-1">{msg}. Start it with <span className="mono">uv run uvicorn lineage_server.app:app</span>.</p>
      </div>
      {retry && <button className="btn" onClick={retry}>Retry</button>}
    </div>
  );
}

export function Loading() {
  return <div className="text-mute text-sm py-10 text-center">Loading…</div>;
}

export function Kpi({ label, value, sub, tone }: { label: string; value: ReactNode; sub?: string; tone?: string }) {
  return (
    <div className="card p-4">
      <p className="text-mute text-sm">{label}</p>
      <p className="text-2xl font-semibold mt-1 tabular-nums" style={tone ? { color: `rgb(var(--${tone}))` } : undefined}>{value}</p>
      {sub && <p className="text-faint text-xs mt-1">{sub}</p>}
    </div>
  );
}

/** The rule that set the outcome, then the other rules that also applied (labelled as such). Falls back to the flat list for old decisions. */
export function Reasons({ primary, secondary, all }: { primary?: string; secondary?: string[]; all: string[] }) {
  if (!primary) return <ul className="text-sm list-disc pl-4 space-y-1">{all.map((r, i) => <li key={i}>{r}</li>)}</ul>;
  return (
    <div className="text-sm">
      <p className="font-medium" data-testid="primary-reason">{primary}</p>
      {!!secondary?.length && (
        <div className="mt-2">
          <p className="text-xs text-faint uppercase tracking-wide">Also applied (secondary)</p>
          <ul className="list-disc pl-4 space-y-0.5 text-mute">{secondary.map((r, i) => <li key={i}>{r}</li>)}</ul>
        </div>
      )}
    </div>
  );
}
