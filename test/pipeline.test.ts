import test from "node:test";
import assert from "node:assert/strict";
import { DeliveryError, Pipeline } from "../src/pipeline.js";
import { loadState } from "../src/store.js";
import { canonGithub } from "../src/util.js";
import { failing, item, recorder, tmpState, withEnv } from "./helpers.js";

const quiet = (t: any) => t.mock.method(console, "error", () => {});
const mk = async (notifiers: any[]) => new Pipeline(await loadState(), notifiers);

test("the same GitHub release arriving via feed, webhook and mail alerts exactly once", async () => {
  await withEnv({ STATE_FILE: await tmpState(), DRY_RUN: undefined }, async () => {
    const rec = recorder();
    const p = await mk([rec]);
    const url = "https://github.com/o/r/releases/tag/v1.0.0";
    const viaFeed = item({ id: "Feed:1", url });
    const viaWebhook = item({ id: "gh-release:9", url, key: canonGithub(url) });
    const viaMail = item({ id: "mail:<a@b>", url: "", key: canonGithub(url) });
    assert.equal(await p.ingest([viaFeed], "all"), 1);
    assert.equal(await p.ingest([viaWebhook], "all"), 0);
    assert.equal(await p.ingest([viaMail], "all"), 0);
    assert.equal(rec.sent.length, 1);
  });
});

test("claim dedupes within a single batch", async () => {
  const p = new Pipeline({ seen: {}, http: {}, baselined: [] }, []);
  assert.equal(p.claim([item({ id: "a" }), item({ id: "a" }), item({ id: "b" })]).length, 2);
});

test("notify=security skips non-security items but still remembers them", async () => {
  const rec = recorder();
  const p = new Pipeline({ seen: {}, http: {}, baselined: [] }, [rec]);
  const fresh = p.claim([item({ id: "n", security: false }), item({ id: "s", security: true })]);
  const r = await p.alert(fresh, "security");
  assert.deepEqual(r.sent.map((i) => i.id), ["s"]);
  assert.equal(r.failed.length, 0);
  assert.equal(p.claim([item({ id: "n" })]).length, 0, "skipped item stays claimed");
});

test("alerts go out oldest-first", async () => {
  const rec = recorder();
  const p = new Pipeline({ seen: {}, http: {}, baselined: [] }, [rec]);
  await p.alert(
    [item({ id: "new", publishedAt: "2026-06-02T00:00:00Z" }), item({ id: "old", publishedAt: "2026-06-01T00:00:00Z" })],
    "all",
  );
  assert.deepEqual(rec.sent.map((i) => i.id), ["old", "new"]);
});

test("one broken channel never blocks the others and the item counts as delivered", async (t) => {
  quiet(t);
  const rec = recorder();
  const p = new Pipeline({ seen: {}, http: {}, baselined: [] }, [failing(), rec]);
  const r = await p.alert([item()], "all");
  assert.equal(rec.sent.length, 1);
  assert.equal(r.sent.length, 1);
  assert.equal(r.failed.length, 0);
});

test("ALL channels failing: item is un-claimed so it can be retried, and ingest throws DeliveryError", async (t) => {
  quiet(t);
  await withEnv({ STATE_FILE: await tmpState(), DRY_RUN: undefined }, async () => {
    const p = await mk([failing("a"), failing("b")]);
    await assert.rejects(p.ingest([item({ id: "x" })], "all"), DeliveryError);
    assert.equal(p.claim([item({ id: "x" })]).length, 1, "still claimable on the next attempt");

    // once a channel recovers, the very same item is delivered
    const rec = recorder();
    const p2 = new Pipeline(p.state, [rec]);
    p2.state.seen = {};
    assert.equal(await p2.ingest([item({ id: "x" })], "all"), 1);
    assert.equal(rec.sent.length, 1);
  });
});

test("state is persisted atomically and reloaded", async () => {
  const file = await tmpState();
  await withEnv({ STATE_FILE: file, DRY_RUN: undefined }, async () => {
    const p = await mk([recorder()]);
    await p.ingest([item({ id: "persist-me" })], "all");
    await p.flush();
    const again = await mk([recorder()]);
    assert.equal(again.claim([item({ id: "persist-me" })]).length, 0);
  });
});
