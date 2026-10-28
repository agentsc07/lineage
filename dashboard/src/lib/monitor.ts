import { useEffect, useState } from "react";
import { api } from "./api";

const MONITOR_IDS = (id: string) => id.startsWith("WATCH.") || id.startsWith("PKG.OSV.");

/**
 * Ids the monitor is the reason for blocking: artifacts in its latest alerting tick (the alerted package and
 * everything flagged downstream) that have no critical finding of their own. An artifact that was already
 * blocked at intake for a critical finding stays plain "Block".
 */
export function useMonitorIds(): Set<string> {
  const [ids, setIds] = useState<Set<string>>(new Set());
  useEffect(() => {
    (async () => {
      const t = await api.latestTick();
      const cand = [...new Set((t?.alerts ?? []).flatMap((a) => [a.artifact_id, ...a.blast_radius.map((n) => n.id)]))].filter((id) => !id.startsWith("ghost:") && !id.startsWith("sbom-group:")); // ghosts have no /artifacts page
      const details = await Promise.all(cand.map((id) => api.artifact(id).catch(() => null)));
      setIds(new Set(cand.filter((_, i) => details[i] && !details[i]!.findings.some((f) => f.severity === "critical" && !MONITOR_IDS(f.id)))));
    })().catch(() => {});
  }, []);
  return ids;
}
