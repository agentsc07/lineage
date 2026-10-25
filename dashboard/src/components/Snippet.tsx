import type { Evidence } from "../lib/types";

/** Renders a file_line evidence item as a code excerpt with the cited line highlighted.
 *  The server only supplies the cited line (`detail`), so neighbouring lines show as an ellipsis gutter. */
export default function Snippet({ ev }: { ev: Evidence }) {
  const m = ev.ref.match(/^(.*):(\d+)$/);
  if (ev.kind !== "file_line" || !m) {
    return (
      <div className="flex gap-3 text-xs">
        <span className="mono text-faint w-14 shrink-0 capitalize">{ev.kind}</span>
        <span className="mono break-all">{ev.ref}</span>
        {ev.detail && <span className="text-mute">{ev.detail}</span>}
      </div>
    );
  }
  const [, file, line] = m;
  const n = Number(line);
  return (
    <figure className="border border-line rounded-md overflow-hidden bg-bg">
      <figcaption className="mono text-mute px-3 py-1.5 border-b border-line bg-raised/60">{file}</figcaption>
      <pre className="mono !text-[12px] leading-5 overflow-x-auto py-1">
        {n > 1 && <Row n="…" text="" />}
        <Row n={String(n)} text={ev.detail || "(line content not captured)"} hit />
        <Row n="…" text="" />
      </pre>
    </figure>
  );
}

function Row({ n, text, hit }: { n: string; text: string; hit?: boolean }) {
  return (
    <div className={`flex ${hit ? "bg-block/10 border-l-2 border-block" : "border-l-2 border-transparent text-faint"}`}>
      <span className="w-10 text-right pr-3 select-none text-faint shrink-0">{n}</span>
      <code className={hit ? "text-ink" : ""}>{text}</code>
    </div>
  );
}
