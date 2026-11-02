import type { Config } from "./types.js";

export class ConfigError extends Error {
  constructor(public problems: string[]) {
    super(`Invalid config:\n  - ${problems.join("\n  - ")}`);
  }
}

const NOTIFY = ["all", "security"];
const nonEmpty = (v: unknown): v is string => typeof v === "string" && v.trim() !== "";

/** Fail fast with every problem listed, instead of a TypeError three minutes into a run. */
export function validateConfig(raw: unknown): Config {
  const c = raw as any;
  if (!c || typeof c !== "object" || Array.isArray(c)) throw new ConfigError(["top level must be a JSON object"]);
  const p: string[] = [];

  if (typeof c.pollSeconds !== "number" || !Number.isFinite(c.pollSeconds) || c.pollSeconds < 30)
    p.push("pollSeconds must be a number >= 30 (be polite to the feed hosts)");

  if (!Array.isArray(c.securityKeywords) || !c.securityKeywords.every(nonEmpty))
    p.push("securityKeywords must be an array of non-empty strings");

  const sources = c.sources ?? [];
  if (!Array.isArray(sources)) p.push("sources must be an array");
  else {
    const names = new Set<string>();
    sources.forEach((s: any, i: number) => {
      const at = `sources[${i}]${nonEmpty(s?.name) ? ` (${s.name})` : ""}`;
      if (!nonEmpty(s?.name)) p.push(`${at}: name is required`);
      else if (names.has(s.name)) p.push(`${at}: duplicate name (names key the dedupe/baseline state)`);
      else names.add(s.name);
      if (!["feed", "kev"].includes(s?.type)) p.push(`${at}: type must be "feed" or "kev"`);
      try {
        if (!/^https?:$/.test(new URL(s?.url).protocol)) throw 0;
      } catch {
        p.push(`${at}: url must be a valid http(s) URL`);
      }
      if (!NOTIFY.includes(s?.notify)) p.push(`${at}: notify must be "all" or "security"`);
    });
  }

  if (c.webhook !== undefined) {
    const w = c.webhook;
    if (!Number.isInteger(w?.port) || w.port < 1 || w.port > 65535) p.push("webhook.port must be an integer 1-65535");
    if (!NOTIFY.includes(w?.notify)) p.push('webhook.notify must be "all" or "security"');
  }

  if (c.mail !== undefined) {
    if (!Array.isArray(c.mail?.rules)) p.push("mail.rules must be an array");
    else
      c.mail.rules.forEach((r: any, i: number) => {
        const at = `mail.rules[${i}]${nonEmpty(r?.name) ? ` (${r.name})` : ""}`;
        if (!nonEmpty(r?.name)) p.push(`${at}: name is required`);
        if (![r?.from, r?.listId, r?.subjectContains].some(nonEmpty))
          p.push(`${at}: needs at least one of from / listId / subjectContains (an empty rule would match every email)`);
        if (r?.notify !== undefined && !NOTIFY.includes(r.notify)) p.push(`${at}: notify must be "all" or "security"`);
        if (r?.requireAuth !== undefined && typeof r.requireAuth !== "boolean") p.push(`${at}: requireAuth must be true/false`);
      });
  }

  if (p.length) throw new ConfigError(p);
  return { ...c, sources } as Config;
}
