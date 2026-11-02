import { XMLParser } from "fast-xml-parser";
import type { Item, SourceCfg } from "./types.js";
import type { State } from "./store.js";
import { isSecurity, strip } from "./util.js";

const xml = new XMLParser({ ignoreAttributes: false, attributeNamePrefix: "@_" });
const UA = "release-radar/0.1 (security release alerts)";

type Cache = { etag?: string; lastModified?: string };

const arr = <T>(v: T | T[] | undefined): T[] => (v == null ? [] : Array.isArray(v) ? v : [v]);
const text = (v: any): string =>
  v == null ? "" : typeof v === "string" ? v : String(v["#text"] ?? v["@_href"] ?? "");
const iso = (s?: string) => {
  if (!s) return undefined;
  const d = new Date(s);
  return isNaN(+d) ? undefined : d.toISOString();
};

/** Conditional GET so a 60s poll costs almost nothing. Returns null on 304. Does NOT touch state. */
export async function fetchSource(src: SourceCfg, state: State): Promise<{ body: string; cache: Cache } | null> {
  const h: Record<string, string> = {
    "user-agent": UA,
    accept: "application/atom+xml,application/rss+xml,application/json,*/*",
  };
  const c = state.http[src.url];
  if (c?.etag) h["if-none-match"] = c.etag;
  if (c?.lastModified) h["if-modified-since"] = c.lastModified;
  const res = await fetch(src.url, { headers: h, signal: AbortSignal.timeout(20_000) });
  if (res.status === 304) return null;
  if (!res.ok) throw new Error(`${src.name}: HTTP ${res.status}`);
  return {
    body: await res.text(),
    cache: { etag: res.headers.get("etag") ?? undefined, lastModified: res.headers.get("last-modified") ?? undefined },
  };
}

/** Pure parser (no I/O). Throws on documents that are not what the source type promises. */
export function parseSource(src: SourceCfg, body: string, keywords: string[], now = new Date().toISOString()): Item[] {
  if (src.type === "kev") {
    const j = JSON.parse(body);
    if (!Array.isArray(j?.vulnerabilities)) throw new Error(`${src.name}: unexpected KEV JSON (no "vulnerabilities" array)`);
    return j.vulnerabilities.map((v: any): Item => ({
      id: `${src.name}:${v.cveID}`,
      source: src.name,
      title: `${v.cveID} actively exploited: ${v.vendorProject} ${v.product}`,
      url: `https://nvd.nist.gov/vuln/detail/${v.cveID}`,
      summary: v.shortDescription,
      publishedAt: iso(v.dateAdded),
      detectedAt: now,
      security: true,
    }));
  }

  const doc = xml.parse(body);
  // A 200 that isn't a feed (captive portal, CDN error page) must be an error, not "zero new items".
  if (!doc?.feed && !doc?.rss) throw new Error(`${src.name}: response is not an Atom/RSS document`);
  const entries: any[] = doc.feed ? arr(doc.feed.entry) : arr(doc.rss?.channel?.item);
  return entries.map((e): Item => {
    const title = strip(text(e.title));
    const summary = strip(text(e.summary ?? e.content ?? e.description)).slice(0, 400);
    const link = Array.isArray(e.link) ? e.link.find((l: any) => l["@_rel"] !== "self") ?? e.link[0] : e.link;
    return {
      id: `${src.name}:${text(e.id ?? e.guid) || text(link) || title}`,
      source: src.name,
      title,
      url: text(link),
      summary,
      publishedAt: iso(text(e.updated ?? e.published ?? e.pubDate)),
      detectedAt: now,
      security: isSecurity(`${title} ${summary}`, keywords),
    };
  });
}

/**
 * Fetch + parse. The ETag/Last-Modified is only remembered AFTER a successful parse; otherwise a bad
 * response would be cached and every later poll would 304 past the items we never processed.
 */
export async function poll(src: SourceCfg, state: State, keywords: string[]): Promise<Item[]> {
  const r = await fetchSource(src, state);
  if (!r) return [];
  const items = parseSource(src, r.body, keywords);
  state.http[src.url] = r.cache;
  return items;
}
