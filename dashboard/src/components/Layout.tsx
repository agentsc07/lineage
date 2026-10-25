import { NavLink, Outlet } from "react-router-dom";
import { useEffect, useState } from "react";
import { useSession } from "../lib/session";

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
  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    try { localStorage.setItem("lineage.theme", theme); } catch { /* ignore */ }
  }, [theme]);
  const pending = sess.filter((s) => s.decision.outcome === "quarantine" && !s.approved).length;

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
