import test from "node:test";
import assert from "node:assert/strict";
import { existsSync, readdirSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import { loadState, saveState } from "../src/store.js";
import { tmpState, withEnv } from "./helpers.js";

test("missing file -> fresh state; save/load roundtrip; no stray .tmp", async () => {
  const f = await tmpState();
  await withEnv({ STATE_FILE: f, DRY_RUN: undefined }, async () => {
    const s = await loadState();
    assert.deepEqual({ ...s }, { seen: {}, http: {}, baselined: [] });
    s.seen.a = "t";
    await saveState(s);
    assert.equal((await loadState()).seen.a, "t");
    assert.ok(!readdirSync(dirname(f)).some((n) => n.endsWith(".tmp")));
  });
});

test("older state files missing newer fields still load", async () => {
  const f = await tmpState();
  writeFileSync(f, JSON.stringify({ seen: { k: "t" } }));
  await withEnv({ STATE_FILE: f, DRY_RUN: undefined }, async () => {
    const s = await loadState();
    assert.deepEqual(s.http, {});
    assert.deepEqual(s.baselined, []);
    assert.equal(s.seen.k, "t");
  });
});

test("corrupt state is moved aside LOUDLY, never silently reset", async (t) => {
  const err = t.mock.method(console, "error", () => {});
  const f = await tmpState();
  writeFileSync(f, "{not json");
  await withEnv({ STATE_FILE: f, DRY_RUN: undefined }, async () => {
    const s = await loadState();
    assert.deepEqual(s.seen, {});
  });
  assert.ok(readdirSync(dirname(f)).some((n) => n.includes(".corrupt-")), "backup kept for forensics");
  assert.match(String(err.mock.calls[0].arguments[0]), /corrupt/);
});

test("dry mode never reads or writes state (so a demo can't use up real alerts)", async () => {
  const f = await tmpState();
  writeFileSync(f, JSON.stringify({ seen: { real: "t" }, http: {}, baselined: ["x"] }));
  await withEnv({ STATE_FILE: f, DRY_RUN: "1" }, async () => {
    const s = await loadState();
    assert.deepEqual(s.seen, {}, "ignores the real file");
    s.seen.demo = "t";
    await saveState(s);
  });
  assert.ok(existsSync(f));
  assert.deepEqual(JSON.parse(require_read(f)).seen, { real: "t" }, "real file untouched");
});
import { readFileSync } from "node:fs";
const require_read = (p: string) => readFileSync(p, "utf8");
