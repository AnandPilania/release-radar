import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { ConfigError, validateConfig } from "../src/config.js";

const good = () => JSON.parse(readFileSync(new URL("../sources.json", import.meta.url), "utf8"));

test("the shipped sources.json is valid", () => {
  const c = validateConfig(good());
  assert.ok(c.sources.length > 0);
});

const problems = (mutate: (c: any) => void): string => {
  const c = good();
  mutate(c);
  try {
    validateConfig(c);
  } catch (e) {
    assert.ok(e instanceof ConfigError);
    return e.message;
  }
  assert.fail("expected ConfigError");
};

test("rejects bad poll interval, source fields and duplicate names, all at once", () => {
  const m = problems((c) => {
    c.pollSeconds = 5;
    c.sources[0].type = "rss";
    c.sources[1].url = "ftp://x";
    c.sources[2].name = c.sources[3].name;
  });
  assert.match(m, /pollSeconds/);
  assert.match(m, /type must be/);
  assert.match(m, /valid http\(s\) URL/);
  assert.match(m, /duplicate name/);
});

test("rejects a mail rule with no matcher (it would match every email)", () => {
  assert.match(problems((c) => (c.mail.rules[0] = { name: "all" })), /at least one of from \/ listId \/ subjectContains/);
});

test("rejects bad webhook port / notify and non-boolean requireAuth", () => {
  const m = problems((c) => {
    c.webhook = { port: 99999, notify: "some" };
    c.mail.rules[1].requireAuth = "yes";
  });
  assert.match(m, /webhook\.port/);
  assert.match(m, /webhook\.notify/);
  assert.match(m, /requireAuth/);
});

test("non-object config is rejected", () => {
  assert.throws(() => validateConfig([]), ConfigError);
  assert.throws(() => validateConfig(null), ConfigError);
});
