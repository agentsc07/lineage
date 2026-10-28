import { useEffect, useState } from "react";
import YAML from "yaml";
import { api, describeError } from "../lib/api";
import { auth } from "../lib/auth";
import { useAsync } from "../lib/useAsync";
import { dt } from "../lib/format";
import type { PolicySignature } from "../lib/types";
import { ErrorBox, Header, Loading } from "../components/ui";

const ROLES = ["owner", "security", "compliance"] as const;
const CLI = "uv run python -m lineage_server.tuf sign new-policy.yaml --key owner=owner.key --key security=security.key --days 90 > update.json";

interface Update { policy: Record<string, any>; signatures: PolicySignature[]; expires_at: string | null }

/** The policy is read here. It changes only through a policy update signed outside the browser with the role keys (2 of 3); this page can
 *  submit such an update but never creates a signature, and no private key ever touches the dashboard. */
export default function Policy() {
  const { data, error, reload } = useAsync(api.policy);
  const [raw, setRaw] = useState("");
  const [update, setUpdate] = useState<Update | null>(null);
  const [parseErr, setParseErr] = useState<string | null>(null);
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [busy, setBusy] = useState(false);
  useEffect(() => { if (data) setMsg(null); }, [data]);

  const parse = (text: string) => {
    setRaw(text); setMsg(null); setUpdate(null); setParseErr(null);
    if (!text.trim()) return;
    try {
      const u = JSON.parse(text);
      if (!u || typeof u.policy !== "object" || !Array.isArray(u.signatures)) throw new Error("not a signed policy update (expected policy, signatures, expires_at)");
      setUpdate({ policy: u.policy, signatures: u.signatures, expires_at: u.expires_at ?? null });
    } catch (e: any) { setParseErr(e.message); }
  };
  const submit = async () => {
    if (!update) return;
    setBusy(true); setMsg(null);
    try {
      const next = await api.putPolicy(update.policy, update.signatures, update.expires_at);
      setMsg({ ok: true, text: `The server verified the signatures and installed policy ${next.version}.` });
      setRaw(""); setUpdate(null); reload();
    } catch (e) { setMsg({ ok: false, text: `The server refused the update: ${describeError(e)}` }); } finally { setBusy(false); }
  };

  if (error) return <div className="page"><ErrorBox msg={error} retry={reload} /></div>;
  if (!data) return <div className="page"><Loading /></div>;
  const need = data.roles_required;
  const roles = update ? new Set(update.signatures.map((s) => s.role)) : new Set<string>();

  return (
    <div className="page">
      <Header title="Policy" sub={`${data.policy.org ?? "Organisation"} rules for admitting artifacts. Read-only here: a change needs ${need} of ${data.roles_total} role signatures made outside the browser.`} />
      <div className="grid lg:grid-cols-[1fr_340px] gap-4 items-start">
        <section className="card">
          <div className="card-h"><h2 className="h-title">Active policy pack</h2><span className="mono text-faint">{data.version}</span></div>
          <textarea className="w-full min-h-[460px] bg-bg text-ink font-mono text-[12.5px] leading-5 p-4 resize-y outline-none rounded-b-lg" spellCheck={false}
            aria-label="Policy YAML (read-only)" readOnly value={YAML.stringify(data.policy)} />
        </section>
        <aside className="flex flex-col gap-4">
          <section className="card">
            <div className="card-h"><h2 className="h-title">Signatures on the active policy</h2><span className="text-sm text-mute">{data.signatures.length} of {need} needed</span></div>
            <ul>{ROLES.map((r) => {
              const live = data.signatures.find((s) => s.role === r);
              return (
                <li key={r} className="px-4 py-3 border-b border-line/60 last:border-0 flex items-center justify-between gap-3">
                  <div><p className="text-sm font-medium capitalize">{r}</p><p className="text-xs text-faint">{live ? `Ed25519 key ${live.key_id}` : "No signature on this version"}</p></div>
                  <span className={`w-2.5 h-2.5 rounded-full ${live ? "bg-allow" : "bg-line"}`} aria-label={live ? "signed" : "unsigned"} />
                </li>);
            })}</ul>
            <p className="text-xs text-faint p-4 border-t border-line">The first policy is installed unsigned on first start (trust on first use); every later one needs the signatures above.</p>
          </section>
          <section className="card p-4 text-sm grid grid-cols-[90px_1fr] gap-y-2">
            <span className="text-mute">Version</span><span className="mono break-all">{data.version}</span>
            <span className="text-mute">Expires</span><span>{data.expires_at ? dt(data.expires_at) : "Never"}</span>
          </section>
        </aside>
      </div>

      <section className="card mt-4" aria-label="Apply a signed policy update">
        <div className="card-h flex-col !items-start !gap-0"><h2 className="h-title">Apply a signed policy update</h2>
          <p className="text-xs text-faint">Admin only. The signing happens on a machine that holds the role keys; this page only carries the result to the server.</p></div>
        <div className="p-4 text-sm space-y-3">
          <p className="text-mute">1. Write the new policy YAML and sign it as at least {need} roles:</p>
          <code className="block mono text-xs bg-bg border border-line rounded-md p-2 break-all">{CLI}</code>
          <p className="text-mute">2. Paste <span className="mono">update.json</span> (or choose the file). The server checks every signature against the role keys it holds, the expiry, and that it is newer than the current policy.</p>
          <input type="file" accept=".json,application/json" className="input" aria-label="Signed update file" onChange={async (e) => { const f = e.target.files?.[0]; if (f) parse(await f.text()); }} />
          <textarea className="w-full min-h-[120px] bg-bg text-ink font-mono text-xs p-3 rounded-md border border-line" aria-label="Signed update JSON" placeholder='{"policy": {...}, "signatures": [...], "expires_at": "..."}' value={raw} onChange={(e) => parse(e.target.value)} />
          {parseErr && <p className="text-block" role="alert">{parseErr}</p>}
          {update && (
            <div className="border border-line rounded-md p-3 bg-bg" data-testid="update-preview">
              <p>Policy version in the update: <span className="mono">{String(update.policy.version ?? "?")}</span> · expires {update.expires_at ? dt(update.expires_at) : "never"}</p>
              <p className="text-mute mt-1">Claims signatures from: {ROLES.filter((r) => roles.has(r)).join(", ") || "nobody"} (these are claims; the server verifies them)</p>
            </div>)}
          <button className="btn btn-primary" disabled={!update || busy || !auth.can("admin")} onClick={submit}>{busy ? "Submitting…" : "Submit to the server"}</button>
          {!auth.can("admin") && <p className="text-xs text-faint">Signed in without the admin role: the server would refuse this.</p>}
          {msg && <p className={msg.ok ? "text-allow" : "text-block"} role="status" data-testid="policy-result">{msg.text}</p>}
        </div>
      </section>
    </div>
  );
}
