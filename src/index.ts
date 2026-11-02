import "./env.js"; // must stay first: loads .env and maps --dry
import { readFile } from "node:fs/promises";
import type { Config, SourceCfg } from "./types.js";
import { ConfigError, validateConfig } from "./config.js";
import { loadState } from "./store.js";
import { buildNotifiers } from "./notifiers.js";
import { Pipeline } from "./pipeline.js";
import { pollOnce } from "./runner.js";
import { startWebhook } from "./webhook.js";
import { startMail } from "./mail.js";
import { argValue, hasArg } from "./flags.js";
import { sleep } from "./util.js";

const once = hasArg("--once");
const replay = Math.max(0, Number(argValue("--replay") ?? 0) || 0);

let cfg: Config;
try {
  cfg = validateConfig(JSON.parse(await readFile(process.env.SOURCES_FILE ?? "sources.json", "utf8")));
} catch (e: any) {
  console.error(e instanceof ConfigError ? e.message : `Cannot read sources file: ${e.message}`);
  process.exit(2);
}

const notifiers = buildNotifiers();
if (!notifiers.length) {
  console.error("No channels configured. Set env vars (see .env.example) or run with --dry.");
  process.exit(1);
}

// --test-alert: prove every configured channel works end-to-end, then exit (0 = all ok).
if (hasArg("--test-alert")) {
  const now = new Date().toISOString();
  const sample = {
    id: "test",
    source: "release-radar",
    title: "Test alert: if you can read this, this channel works",
    url: "https://example.com/test",
    summary: "Sent by `--test-alert`. Nothing is wrong.",
    publishedAt: now,
    detectedAt: now,
    security: false,
  };
  const { render } = await import("./notifiers.js");
  let bad = 0;
  for (const n of notifiers) {
    try {
      await n.send(sample, render(sample));
      console.log(`  ok    ${n.name}`);
    } catch (e: any) {
      bad++;
      console.error(`  FAIL  ${n.name}: ${e.message}`);
    }
  }
  process.exit(bad ? 1 : 0);
}

const pipe = new Pipeline(await loadState(), notifiers);
console.log(`channels: ${notifiers.map((n) => n.name).join(", ")} | poll sources: ${cfg.sources.length}`);

const stop = new AbortController();
for (const sig of ["SIGINT", "SIGTERM"] as const)
  process.once(sig, () => {
    console.log(`${sig} received, shutting down`);
    stop.abort();
    setTimeout(() => process.exit(1), 10_000).unref(); // hard stop if something hangs
  });

let failures = 0;
async function loop(src: SourceCfg) {
  let backoff = 0;
  if (!once) await sleep(Math.random() * 5000, stop.signal); // jitter
  while (!stop.signal.aborted) {
    try {
      await pollOnce(src, pipe, cfg, { replay });
      backoff = 0;
    } catch (e: any) {
      failures++;
      backoff = Math.min(backoff ? backoff * 2 : 30, 900);
      console.error(`[${src.name}] ${e.message} (retry in ${backoff}s extra)`);
    }
    if (once) return;
    await sleep((cfg.pollSeconds + backoff) * 1000, stop.signal);
  }
}

const jobs: Promise<unknown>[] = cfg.sources.map(loop);

if (!once) {
  if (cfg.webhook) {
    const secret = process.env.GITHUB_WEBHOOK_SECRET;
    if (!secret) console.error("[webhook] GITHUB_WEBHOOK_SECRET not set, webhook disabled");
    else {
      const srv = startWebhook({
        port: cfg.webhook.port,
        host: process.env.WEBHOOK_HOST,
        secret,
        keywords: cfg.securityKeywords,
        onItem: async (i) => void (await pipe.ingest([i], cfg.webhook!.notify)),
      });
      jobs.push(new Promise<void>((res) => srv.once("close", () => res())));
      stop.signal.addEventListener("abort", () => {
        srv.close();
        srv.closeAllConnections();
      });
    }
  }
  if (cfg.mail) {
    if (!process.env.IMAP_HOST || !process.env.IMAP_USER || !process.env.IMAP_PASS)
      console.error("[mail] IMAP_HOST/IMAP_USER/IMAP_PASS not set, mail listener disabled");
    else
      jobs.push(
        startMail({
          rules: cfg.mail.rules,
          keywords: cfg.securityKeywords,
          state: pipe.state,
          persist: () => pipe.persist(),
          onItem: async (i, notify) => void (await pipe.ingest([i], notify)),
          signal: stop.signal,
        }),
      );
  }
}

await Promise.all(jobs);
await pipe.flush();
process.exit(once && failures ? 1 : 0);
