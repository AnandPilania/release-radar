import test from "node:test";
import assert from "node:assert/strict";
import { Pipeline } from "../src/pipeline.js";
import { loadState } from "../src/store.js";
import { pollOnce } from "../src/runner.js";
import type { SourceCfg } from "../src/types.js";
import { atom, failing, recorder, stubFetch, tmpState, withEnv } from "./helpers.js";

const src: SourceCfg = { name: "Laravel", type: "feed", url: "https://example.com/releases.atom", notify: "all" };
const cfg = { securityKeywords: ["CVE-", "security"] };
const e = (n: number, extra = "") => ({
  id: `tag:${n}`, title: `v1.${n}.0`, href: `https://github.com/o/r/releases/tag/v1.${n}.0`,
  updated: `2026-06-0${n}T10:00:00Z`, summary: extra,
});
const quiet = (t: any) => t.mock.method(console, "log", () => {});

test("first poll baselines silently; only NEW releases alert afterwards; repeats never re-alert", async (t) => {
  quiet(t);
  await withEnv({ STATE_FILE: await tmpState(), DRY_RUN: undefined }, async () => {
    let feed = atom([e(1), e(2)]);
    const s = stubFetch(() => new Response(feed, { status: 200 }));
    try {
      const rec = recorder();
      const pipe = new Pipeline(await loadState(), [rec]);

      await pollOnce(src, pipe, cfg);
      assert.equal(rec.sent.length, 0, "existing releases must not spam on first start");
      assert.deepEqual(pipe.state.baselined, ["Laravel"]);

      feed = atom([e(1), e(2), e(3, "Security fix for CVE-2026-5")]);
      await pollOnce(src, pipe, cfg);
      assert.equal(rec.sent.length, 1);
      assert.equal(rec.sent[0].title, "v1.3.0");
      assert.equal(rec.sent[0].security, true);

      await pollOnce(src, pipe, cfg);
      assert.equal(rec.sent.length, 1, "same feed again -> no duplicate");
    } finally { s.restore(); }
  });
});

test("--replay N alerts the newest N on first run (demo mode) and still baselines the rest", async (t) => {
  quiet(t);
  await withEnv({ STATE_FILE: await tmpState(), DRY_RUN: undefined }, async () => {
    const s = stubFetch(() => new Response(atom([e(1), e(2), e(3)]), { status: 200 }));
    try {
      const rec = recorder();
      const pipe = new Pipeline(await loadState(), [rec]);
      await pollOnce(src, pipe, cfg, { replay: 2 });
      assert.deepEqual(rec.sent.map((i) => i.title).sort(), ["v1.2.0", "v1.3.0"]);
      await pollOnce(src, pipe, cfg, { replay: 2 });
      assert.equal(rec.sent.length, 2, "nothing replayed twice");
    } finally { s.restore(); }
  });
});

test("an alert that reaches no channel is retried on the next poll (not lost behind a 304)", async (t) => {
  quiet(t);
  const errs = t.mock.method(console, "error", () => {});
  await withEnv({ STATE_FILE: await tmpState(), DRY_RUN: undefined }, async () => {
    let published = 1;
    // A well-behaved server: if the client presents the current ETag it gets 304 (and would never see the release again).
    const s = stubFetch((_u, init) => {
      const etag = `"E${published}"`;
      if ((init.headers as any)["if-none-match"] === etag) return new Response(null, { status: 304 });
      return new Response(atom(Array.from({ length: published }, (_, k) => e(k + 1))), { status: 200, headers: { etag } });
    });
    try {
      const pipe = new Pipeline(await loadState(), [failing()]);
      await pollOnce(src, pipe, cfg); // silent baseline of v1.1.0
      assert.ok(pipe.state.http[src.url], "etag cached after a successful poll");

      published = 2; // v1.2.0 appears, but every channel is down
      await pollOnce(src, pipe, cfg);
      assert.equal(pipe.state.http[src.url], undefined, "cache dropped so the next poll refetches instead of getting a 304");
      assert.ok(errs.mock.calls.some((c) => /reached no channel/.test(String(c.arguments[0]))));

      const rec = recorder(); // channel recovers
      await pollOnce(src, new Pipeline(pipe.state, [rec]), cfg);
      assert.equal(s.calls.at(-1)!.headers["if-none-match"], undefined, "refetched unconditionally");
      assert.deepEqual(rec.sent.map((i) => i.title), ["v1.2.0"], "the missed alert was delivered after recovery");
    } finally { s.restore(); }
  });
});

test("a source that errors does not corrupt state for a later good poll", async (t) => {
  quiet(t);
  await withEnv({ STATE_FILE: await tmpState(), DRY_RUN: undefined }, async () => {
    let ok = false;
    const s = stubFetch(() => (ok ? new Response(atom([e(1)]), { status: 200 }) : new Response("<html>oops</html>", { status: 200 })));
    try {
      const pipe = new Pipeline(await loadState(), [recorder()]);
      await assert.rejects(pollOnce(src, pipe, cfg), /not an Atom\/RSS/);
      assert.deepEqual(pipe.state.baselined, [], "failed first poll must not count as baselined");
      ok = true;
      await pollOnce(src, pipe, cfg);
      assert.deepEqual(pipe.state.baselined, ["Laravel"]);
    } finally { s.restore(); }
  });
});
