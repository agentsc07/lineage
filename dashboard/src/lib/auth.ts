// The signed-in user. Tokens live in sessionStorage (cleared when the tab closes) and are sent as a bearer token.
// Every user who has signed in on this tab is remembered, so the sidebar can switch between them without signing out.
import { useSyncExternalStore } from "react";

export interface Me { name: string; email: string; roles: string[]; env: string; auth_required: boolean }
export interface Known { name: string; token: string; roles?: string[] }
const KEY = "lineage.token", KNOWN = "lineage.known";
let token: string | null = null;
let me: Me | null = null;
let known: Known[] = [];
try { token = sessionStorage.getItem(KEY); known = JSON.parse(sessionStorage.getItem(KNOWN) ?? "[]"); } catch { token = null; known = []; }
const subs = new Set<() => void>();
const emit = () => subs.forEach((f) => f());
const save = () => { try { sessionStorage.setItem(KNOWN, JSON.stringify(known)); } catch { /* storage unavailable */ } };

export const auth = {
  token: () => token,
  me: () => me,
  known: () => known,
  setToken(t: string | null) {
    token = t; me = null;
    try { t ? sessionStorage.setItem(KEY, t) : sessionStorage.removeItem(KEY); } catch { /* storage unavailable */ }
    emit();
  },
  /** Switch to a remembered user. The page stays where it is; only the identity changes. */
  switchTo(t: string) {
    token = t;
    try { sessionStorage.setItem(KEY, t); } catch { /* storage unavailable */ }
    emit();
  },
  setMe(m: Me | null) {
    me = m;
    if (m && token) { known = [...known.filter((k) => k.token !== token), { name: m.name, token, roles: m.roles }]; save(); }
    emit();
  },
  /** Demo only: remember users the dev server lists in /demo-users.json ({name: token}). Their roles show once each has been used. */
  preload(users: Record<string, string>) {
    for (const [name, t] of Object.entries(users)) if (!known.some((k) => k.token === t)) known = [...known, { name, token: t }];
    save(); emit();
  },
  can: (...roles: string[]) => !!me && (me.roles.includes("admin") || roles.some((r) => me!.roles.includes(r))),
};
export function useMe(): { token: string | null; me: Me | null; known: Known[] } {
  const snap = useSyncExternalStore((f) => { subs.add(f); return () => subs.delete(f); }, () => `${token}|${me?.name}|${known.length}`);
  void snap;
  return { token, me, known };
}
