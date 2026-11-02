/**
 * Pre-release check: fetch every configured source exactly as the poller would and report what comes back.
 * Catches dead URLs, HTML-instead-of-feed responses and silently-empty feeds. Needs network. No state, no alerts.
 */
import "./env.js";
import { readFile } from "node:fs/promises";
import { validateConfig } from "./config.js";
import { fetchSource, parseSource } from "./sources.js";

const cfg = validateConfig(JSON.parse(await readFile(process.env.SOURCES_FILE ?? "sources.json", "utf8")));
let bad = 0;
for (const src of cfg.sources) {
  try {
    const r = await fetchSource(src, { seen: {}, http: {}, baselined: [] });
    const items = parseSource(src, r!.body, cfg.securityKeywords);
    const sec = items.filter((i) => i.security).length;
    const newest = items.map((i) => i.publishedAt ?? "").sort().at(-1) || "no dates";
    const warn = items.length === 0 ? "  <-- EMPTY" : "";
    if (items.length === 0) bad++;
    console.log(`ok    ${src.name.padEnd(22)} ${String(items.length).padStart(5)} items, ${String(sec).padStart(4)} flagged security, newest ${newest}${warn}`);
  } catch (e: any) {
    bad++;
    console.log(`FAIL  ${src.name.padEnd(22)} ${e.message}`);
  }
}
console.log(bad ? `\n${bad} source(s) need attention` : "\nall sources healthy");
process.exit(bad ? 1 : 0);
