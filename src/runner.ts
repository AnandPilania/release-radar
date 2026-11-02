import type { Config, SourceCfg } from "./types.js";
import type { Pipeline } from "./pipeline.js";
import { poll } from "./sources.js";

/**
 * One poll of one source: fetch, dedupe, alert, persist.
 * - First ever poll of a source is a silent baseline (optionally replaying the newest N, for demos).
 * - If an alert reaches no channel, the item is un-claimed AND the HTTP cache is dropped, so the next
 *   poll refetches the feed instead of getting a 304 and never retrying.
 */
export async function pollOnce(
  src: SourceCfg,
  pipe: Pipeline,
  cfg: Pick<Config, "securityKeywords">,
  o: { replay?: number } = {},
): Promise<void> {
  const items = await poll(src, pipe.state, cfg.securityKeywords);
  const firstRun = !pipe.state.baselined.includes(src.name);
  const fresh = pipe.claim(items);

  let toAlert = fresh;
  if (firstRun) {
    pipe.state.baselined.push(src.name);
    const n = o.replay ?? 0;
    console.log(`[${src.name}] baselined ${fresh.length} existing items${n > 0 ? `, replaying newest ${n}` : ""}`);
    toAlert =
      n > 0 ? [...fresh].sort((a, b) => (b.publishedAt ?? "").localeCompare(a.publishedAt ?? "")).slice(0, n) : [];
  }

  if (toAlert.length) {
    const r = await pipe.deliver(toAlert, src.notify);
    if (r.failed.length) {
      delete pipe.state.http[src.url];
      console.error(`[${src.name}] ${r.failed.length} alert(s) reached no channel; will retry next poll`);
    }
  }
  if (firstRun || fresh.length) await pipe.persist();
}
