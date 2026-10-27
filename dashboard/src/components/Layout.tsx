import { NavLink, Outlet } from "react-router-dom";
import { useEffect, useState } from "react";
import { useSession } from "../lib/session";
import { api } from "../lib/api";
import { auth, useMe } from "../lib/auth";

const nav = [
  { to: "/", label: "Overview", end: true },
  { to: "/catalogue", label: "Catalogue" },
  { to: "/intake", label: "Intake" },
  { to: "/approvals", label: "Approvals" },
  { to: "/graph", label: "Lineage" },
  { to: "/policy", label: "Policy" },
  { to: "/bench", label: "Bench" },
];

export default function Layout() {
  const [theme, setTheme] = useState(document.documentElement.dataset.theme ?? "dark");
  const sess = useSession();
  const { token, me } = useMe();
  const [loginErr, setLoginErr] = useState<string | null>(null);
  const [draft, setDraft] = useState("");
  useEffect(() => {
    if (!token) return;
    api.whoami().then((m) => { auth.setMe(m); setLoginErr(null); }).catch((e) => { auth.setToken(null); setLoginErr(String(e.message ?? e)); });
  }, [token]);
  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    try { localStorage.setItem("lineage.theme", theme); } catch { /* ignore */ }
  }, [theme]);
  const pending = sess.filter((s) => s.decision.outcome === "quarantine" && !s.approved).length;

  if (!token || !me) {
    return (
      <div className="min-h-screen flex items-center justify-center p-6">
        <form className="card p-6 w-full max-w-sm" onSubmit={(e) => { e.preventDefault(); if (draft.trim()) { setLoginErr(null); auth.setToken(draft.trim()); } }}>
          <h1 className="font-semibold tracking-tight text-lg mb-1">Lineage</h1>
          <p className="text-sm text-mute mb-4">Paste your API token. It is kept for this tab only.</p>
          <input className="input font-mono" type="password" autoFocus placeholder="lg_…" value={draft} onChange={(e) => setDraft(e.target.value)} aria-label="API token" />
          {loginErr && <p className="text-sm text-block mt-3">{loginErr}</p>}
          <button className="btn btn-primary mt-4 w-full" disabled={!draft.trim() || (!!token && !me)}>{token && !me ? "Checking…" : "Sign in"}</button>
        </form>
      </div>
    );
  }
  return (
    <div className="flex min-h-full">
      <aside className="w-52 shrink-0 border-r border-line bg-panel flex flex-col sticky top-0 h-screen">
        <div className="px-5 h-14 flex items-center gap-2.5 border-b border-line">
          <svg width="20" height="20" viewBox="0 0 20 20" aria-hidden>
            <circle cx="4" cy="10" r="2.4" fill="rgb(var(--accent))" />
            <circle cx="16" cy="4.5" r="2.4" fill="rgb(var(--allow))" />
            <circle cx="16" cy="15.5" r="2.4" fill="rgb(var(--allow))" />
            <path d="M6 9 14 5M6 11l8 4" stroke="rgb(var(--faint))" strokeWidth="1.4" />
          </svg>
          <span className="font-semibold tracking-tight">Lineage</span>
        </div>
        <nav className="p-2 flex-1 flex flex-col gap-0.5" aria-label="Main">
          {nav.map((n) => (
            <NavLink key={n.to} to={n.to} end={n.end}
              className={({ isActive }) => `px-3 h-8 flex items-center justify-between rounded-md text-sm transition-colors ${isActive ? "bg-raised text-ink font-medium" : "text-mute hover:text-ink hover:bg-raised/60"}`}>
              {n.label}
              {n.to === "/approvals" && pending > 0 && <span className="text-xs bg-quar/15 text-quar rounded px-1.5">{pending}</span>}
            </NavLink>
          ))}
        </nav>
        <div className="px-3 pt-3 text-xs text-mute">
          <p className="text-ink font-medium truncate">{me.name}</p>
          <p className="truncate">{me.roles.join(", ")}</p>
          <button className="underline mt-1" onClick={() => auth.setToken(null)}>Sign out</button>
        </div>
        <div className="p-3 border-t border-line flex items-center justify-between">
          <span className="text-xs text-mute">Apollo Health AI</span>
          <button className="btn !h-7 !px-2 text-xs" onClick={() => setTheme(theme === "dark" ? "light" : "dark")} aria-label="Toggle colour theme">
            {theme === "dark" ? "Light" : "Dark"}
          </button>
        </div>
      </aside>
      <main className="flex-1 min-w-0"><Outlet /></main>
    </div>
  );
}
