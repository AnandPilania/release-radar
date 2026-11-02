import type { Dep } from "./manifests.js";
import { severityOf, type Severity } from "./cvss.js";
import { sleep } from "../util.js";

export interface Vuln {
  id: string;
  aliases: string[];
  summary: string;
  severity: Severity;
  score?: number;
  fixed: string[];
  url: string;
}

const base = () => (process.env.OSV_API_URL ?? "https://api.osv.dev").replace(/\/+$/, "");
export const depKey = (d: Pick<Dep, "ecosystem" | "name" | "version">) => `${d.ecosystem}:${d.name}@${d.version}`;

async function api(path: string, body?: unknown, attempts = 3): Promise<any> {
  for (let n = 1; ; n++) {
    try {
      const r = await fetch(base() + path, {
        method: body ? "POST" : "GET",
        headers: body ? { "content-type": "application/json" } : undefined,
        body: body ? JSON.stringify(body) : undefined,
        signal: AbortSignal.timeout(30_000),
      });
      if (r.ok) return await r.json();
      if (r.status !== 429 && r.status < 500) throw Object.assign(new Error(`OSV ${path.split("/")[2] ?? path} -> HTTP ${r.status}`), { fatal: true });
      if (n >= attempts) throw new Error(`OSV -> HTTP ${r.status}`);
    } catch (e: any) {
      if (e.fatal || n >= attempts) throw new Error(e.fatal ? e.message : `Cannot reach OSV (${e.cause?.code ?? e.message}). Check your network or OSV_API_URL.`);
    }
    await sleep(500 * n);
  }
}

const parseVersion = (v: string) => {
  const s = v.replace(/^v/i, "").split("+")[0];
  const m = s.match(/^(\d+(?:\.\d+)*)(.*)$/);
  return m ? { nums: m[1].split(".").map(Number), pre: m[2].replace(/^[-._]/, "") } : { nums: [0], pre: s };
};

/** Ascending version compare for "fixed in" suggestions: numeric parts first; a pre-release (1.0.0-beta.1, 1.0.0rc1) sorts before its release; ".postN" sorts after it. */
export function cmpVersion(a: string, b: string): number {
  const [x, y] = [parseVersion(a), parseVersion(b)];
  for (let i = 0; i < Math.max(x.nums.length, y.nums.length); i++) if ((x.nums[i] ?? 0) !== (y.nums[i] ?? 0)) return (x.nums[i] ?? 0) - (y.nums[i] ?? 0);
  if (x.pre === y.pre) return 0;
  const rank = (p: string) => (p === "" ? 1 : /^post/i.test(p) ? 2 : 0);
  if (rank(x.pre) !== rank(y.pre)) return rank(x.pre) - rank(y.pre);
  const ids = (p: string) => p.split(/[.\-_]/);
  const [i, j] = [ids(x.pre), ids(y.pre)];
  for (let k = 0; k < Math.max(i.length, j.length); k++) {
    if (i[k] === undefined) return -1;
    if (j[k] === undefined) return 1;
    const [n, m] = [/^\d+$/.test(i[k]), /^\d+$/.test(j[k])];
    const c = n && m ? Number(i[k]) - Number(j[k]) : n ? -1 : m ? 1 : i[k].localeCompare(j[k]);
    if (c) return c;
  }
  return 0;
}

export function toVuln(v: any, dep: Pick<Dep, "ecosystem" | "name">): Vuln {
  const fixed = new Set<string>();
  for (const a of v.affected ?? [])
    if (a.package?.ecosystem === dep.ecosystem && String(a.package?.name).toLowerCase() === dep.name.toLowerCase())
      for (const r of a.ranges ?? []) if (r.type !== "GIT") for (const e of r.events ?? []) if (e.fixed) fixed.add(String(e.fixed)); // GIT ranges hold commit hashes, not versions
  const { severity, score } = severityOf(v);
  const text = String(v.summary || String(v.details ?? "").split("\n")[0] || "No description provided").trim();
  return {
    id: v.id,
    aliases: (v.aliases ?? []).filter((x: string) => x !== v.id),
    summary: text.length > 160 ? text.slice(0, 157) + "..." : text,
    severity,
    score,
    fixed: [...fixed].sort(cmpVersion),
    url: `https://osv.dev/vulnerability/${v.id}`,
  };
}

/** Which of these exact package versions have known vulnerabilities? Returns depKey -> vulns (only non-empty). */
export async function lookup(deps: Dep[]): Promise<Map<string, Vuln[]>> {
  const ids = new Map<string, Set<string>>(); // depKey -> vuln ids
  let pending = deps.map((d, i) => ({ i, token: undefined as string | undefined }));
  while (pending.length) {
    const next: typeof pending = [];
    for (let at = 0; at < pending.length; at += 500) {
      const chunk = pending.slice(at, at + 500);
      const res = await api("/v1/querybatch", {
        queries: chunk.map(({ i, token }) => ({
          package: { name: deps[i].name, ecosystem: deps[i].ecosystem },
          version: deps[i].version,
          ...(token ? { page_token: token } : {}),
        })),
      });
      (res.results ?? []).forEach((r: any, k: number) => {
        const { i } = chunk[k];
        for (const v of r?.vulns ?? []) (ids.get(depKey(deps[i])) ?? ids.set(depKey(deps[i]), new Set()).get(depKey(deps[i]))!).add(v.id);
        if (r?.next_page_token) next.push({ i, token: r.next_page_token });
      });
    }
    pending = next;
  }

  const records = new Map<string, any>();
  const all = [...new Set([...ids.values()].flatMap((s) => [...s]))];
  let cursor = 0;
  await Promise.all(
    Array.from({ length: Math.min(8, all.length) }, async () => {
      while (cursor < all.length) {
        const id = all[cursor++];
        records.set(id, await api(`/v1/vulns/${encodeURIComponent(id)}`));
      }
    }),
  );

  const out = new Map<string, Vuln[]>();
  for (const d of deps) {
    const found = [...(ids.get(depKey(d)) ?? [])]
      .map((id) => records.get(id))
      .filter((r) => r && !r.withdrawn)
      .map((r) => toVuln(r, d));
    if (found.length) out.set(depKey(d), found);
  }
  return out;
}
