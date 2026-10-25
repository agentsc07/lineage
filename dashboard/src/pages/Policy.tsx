import { useEffect, useState } from "react";
import YAML from "yaml";
import { api } from "../lib/api";
import { useAsync } from "../lib/useAsync";
import { dt } from "../lib/format";
import type { PolicySignature } from "../lib/types";
import { ErrorBox, Header, Loading } from "../components/ui";

const ROLES = ["owner", "security", "compliance"] as const;

async function digest(text: string, role: string) {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(`${role}\n${text}`));
  return btoa(String.fromCharCode(...new Uint8Array(buf)));
}

export default function Policy() {
  const { data, error, reload } = useAsync(api.policy);
  const [text, setText] = useState("");
  const [editing, setEditing] = useState(false);
  const [sigs, setSigs] = useState<PolicySignature[]>([]);
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => { if (data) { setText(YAML.stringify(data.policy)); setSigs([]); setEditing(false); } }, [data]);
  if (error) return <div className="page"><ErrorBox msg={error} retry={reload} /></div>;
  if (!data) return <div className="page"><Loading /></div>;

  let parsed: object | null = null; let parseErr: string | null = null;
  try { parsed = YAML.parse(text); } catch (e: any) { parseErr = e.message.split("\n")[0]; }
  const changed = text !== YAML.stringify(data.policy);
  const need = data.roles_required;
  const signed = new Set(sigs.map((s) => s.role));
  const enough = signed.size >= need;

  const toggle = async (role: string) => {
    setSigs(signed.has(role) ? sigs.filter((s) => s.role !== role) : [...sigs, { role, key_id: "dashboard-" + role, signature: await digest(text, role) }]);
  };
  const edit = (v: string) => { setText(v); setSigs([]); setMsg(null); }; // any edit invalidates collected approvals
  const save = async () => {
    if (!parsed) return;
    setBusy(true); setMsg(null);
    try {
      const next = await api.putPolicy(parsed, sigs, data.expires_at ?? null);
      setMsg({ ok: true, text: `Policy ${next.version} saved with ${next.signatures.length} approvals` });
      reload();
    } catch (e: any) { setMsg({ ok: false, text: e.message }); } finally { setBusy(false); }
  };

  return (
    <div className="page">
      <Header title="Policy" sub={`${data.policy.org ?? "Organisation"} rules for admitting artifacts. Changes need ${need} of ${data.roles_total} role approvals.`}
        actions={!editing ? <button className="btn" onClick={() => setEditing(true)}>Edit policy</button> : <button className="btn" onClick={() => { setText(YAML.stringify(data.policy)); setEditing(false); setSigs([]); setMsg(null); }}>Discard changes</button>} />
      <div className="grid lg:grid-cols-[1fr_320px] gap-4 items-start">
        <section className="card">
          <div className="card-h"><h2 className="h-title">Policy pack</h2><span className="mono text-faint">{data.version}</span></div>
          <textarea className="w-full min-h-[460px] bg-bg text-ink font-mono text-[12.5px] leading-5 p-4 resize-y outline-none rounded-b-lg" spellCheck={false}
            aria-label="Policy YAML" readOnly={!editing} value={text} onChange={(e) => edit(e.target.value)} />
          {parseErr && <p className="px-4 py-2 text-sm text-block border-t border-line">Invalid YAML: {parseErr}</p>}
        </section>
        <aside className="flex flex-col gap-4">
          <section className="card">
            <div className="card-h"><h2 className="h-title">Approvals</h2><span className={`text-sm ${enough ? "text-allow" : "text-mute"}`}>{(editing ? signed.size : data.signatures.length)} of {need} needed</span></div>
            <ul>{ROLES.map((r) => {
              const live = data.signatures.find((s) => s.role === r);
              const on = editing ? signed.has(r) : !!live;
              return (
                <li key={r} className="px-4 py-3 border-b border-line/60 last:border-0 flex items-center justify-between gap-3">
                  <div><p className="text-sm font-medium capitalize">{r}</p><p className="text-xs text-faint">{on ? (editing ? "Approving this change" : `Key ${live!.key_id}`) : "Not signed"}</p></div>
                  {editing ? <button className={`btn !h-7 ${on ? "" : "btn-primary"}`} disabled={!changed || !!parseErr} onClick={() => toggle(r)}>{on ? "Withdraw" : "Approve"}</button>
                    : <span className={`w-2.5 h-2.5 rounded-full ${on ? "bg-allow" : "bg-line"}`} aria-label={on ? "signed" : "unsigned"} />}
                </li>);
            })}</ul>
            {editing && <div className="p-4 border-t border-line">
              <button className="btn btn-primary w-full" disabled={!changed || !!parseErr || !enough || busy} onClick={save}>{busy ? "Saving…" : "Save new policy"}</button>
              <p className="text-xs text-faint mt-2">{!changed ? "Edit the YAML to propose a change." : !enough ? `Collect ${need - signed.size} more approval${need - signed.size === 1 ? "" : "s"} to save.` : "Ready to save."} Approvals reset when the text changes.</p>
              <p className="text-xs text-faint mt-1">Dashboard approvals are SHA-256 digests, not Ed25519 keys; use the CLI for production signing.</p>
            </div>}
            {msg && <p className={`px-4 pb-4 text-sm ${msg.ok ? "text-allow" : "text-block"}`} role="status">{msg.text}</p>}
          </section>
          <section className="card p-4 text-sm grid grid-cols-[90px_1fr] gap-y-2">
            <span className="text-mute">Version</span><span className="mono break-all">{data.version}</span>
            <span className="text-mute">Expires</span><span>{data.expires_at ? dt(data.expires_at) : "Never"}</span>
          </section>
        </aside>
      </div>
    </div>
  );
}
