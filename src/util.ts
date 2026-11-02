export const strip = (s: string) => s.replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim();

const esc = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const cache = new WeakMap<string[], RegExp | null>();

/**
 * Keyword matcher with word-ish boundaries so "RCE" no longer matches "source"/"force".
 * Keywords start on a boundary; short ones (<=4 chars, e.g. RCE) must also end on one,
 * longer ones act as stems ("vulnerab" still matches "vulnerability").
 */
function compile(keywords: string[]): RegExp | null {
  if (cache.has(keywords)) return cache.get(keywords)!;
  const parts = keywords
    .map((k) => k.trim())
    .filter(Boolean)
    .map((k) => {
      const pre = /^[a-z0-9]/i.test(k) ? "(?<![a-z0-9])" : "";
      const post = /[a-z0-9]$/i.test(k) && k.length <= 4 ? "(?![a-z0-9])" : "";
      return pre + esc(k) + post;
    });
  const re = parts.length ? new RegExp(parts.join("|"), "i") : null;
  cache.set(keywords, re);
  return re;
}

export const isSecurity = (text: string, keywords: string[]): boolean => !!compile(keywords)?.test(text);

/** github.com URLs are canonicalised so webhook / email / atom poll all collapse to one key. */
export function canonGithub(url: string | undefined): string | undefined {
  if (!url) return undefined;
  try {
    const u = new URL(url);
    if (u.hostname.toLowerCase() !== "github.com") return undefined;
    return `github.com${u.pathname.replace(/\/+$/, "")}`.toLowerCase();
  } catch {
    return undefined;
  }
}

/** Host only. Webhook URLs and bot tokens live in the path, so error logs must never print the full URL. */
export const safeHost = (url: string): string => {
  try {
    return new URL(url).host;
  } catch {
    return "invalid-url";
  }
};

/** Sleep that wakes early when the signal aborts (graceful shutdown). */
export const sleep = (ms: number, signal?: AbortSignal) =>
  new Promise<void>((resolve) => {
    if (signal?.aborted) return resolve();
    const t = setTimeout(done, ms);
    function done() {
      clearTimeout(t);
      signal?.removeEventListener("abort", done);
      resolve();
    }
    signal?.addEventListener("abort", done, { once: true });
  });
