// The signed-in user. The token lives in sessionStorage (cleared when the tab closes) and is sent as a bearer token.
import { useSyncExternalStore } from "react";

export interface Me { name: string; email: string; roles: string[]; env: string; auth_required: boolean }
const KEY = "lineage.token";
let token: string | null = null;
let me: Me | null = null;
try { token = sessionStorage.getItem(KEY); } catch { token = null; }
const subs = new Set<() => void>();
const emit = () => subs.forEach((f) => f());

export const auth = {
  token: () => token,
  me: () => me,
  setToken(t: string | null) {
    token = t; me = null;
    try { t ? sessionStorage.setItem(KEY, t) : sessionStorage.removeItem(KEY); } catch { /* storage unavailable */ }
    emit();
  },
  setMe(m: Me | null) { me = m; emit(); },
  can: (...roles: string[]) => !!me && (me.roles.includes("admin") || roles.some((r) => me!.roles.includes(r))),
};
export function useMe(): { token: string | null; me: Me | null } {
  const snap = useSyncExternalStore((f) => { subs.add(f); return () => subs.delete(f); }, () => `${token}|${me?.name}`);
  void snap;
  return { token, me };
}
