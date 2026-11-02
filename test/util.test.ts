import test from "node:test";
import assert from "node:assert/strict";
import { isSecurity, canonGithub, safeHost, strip, sleep } from "../src/util.js";

const KW = ["CVE-", "security", "vulnerab", "remote code", "RCE", "out-of-bounds", "advisory", "exploit"];

test("isSecurity flags real security signals", () => {
  for (const t of [
    "CVE-2026-1234 fixed in 8.4.2",
    "Node.js Security Release 22.1.0",
    "Fixes a vulnerability in the parser",
    "Pre-auth RCE in widget",
    "RCE",
    "Remote code execution via upload",
    "out-of-bounds read in decoder",
    "Published GitHub advisory",
    "Actively exploited in the wild",
  ])
    assert.equal(isSecurity(t, KW), true, t);
});

test("isSecurity does NOT flag ordinary words that merely contain 'rce'", () => {
  for (const t of [
    "Improved resource loading and performance",
    "Source maps now enforced",
    "Force push protection",
    "Brotli 1.2: small refactor",
  ])
    assert.equal(isSecurity(t, KW), false, t);
});

test("isSecurity with no keywords never matches", () => {
  assert.equal(isSecurity("CVE-2026-1 RCE", []), false);
  assert.equal(isSecurity("anything", ["", "  "]), false);
});

test("canonGithub collapses case, trailing slashes and ignores non-GitHub URLs", () => {
  assert.equal(
    canonGithub("https://GitHub.com/Laravel/Framework/releases/tag/v11.0.0/"),
    "github.com/laravel/framework/releases/tag/v11.0.0",
  );
  assert.equal(canonGithub("https://example.com/a"), undefined);
  assert.equal(canonGithub("not a url"), undefined);
  assert.equal(canonGithub(undefined), undefined);
});

test("safeHost never exposes the path", () => {
  assert.equal(safeHost("https://hooks.slack.com/services/T0/B0/SECRET"), "hooks.slack.com");
  assert.equal(safeHost("garbage"), "invalid-url");
});

test("strip removes tags and collapses whitespace", () => {
  assert.equal(strip("<p>Hello\n  <b>world</b></p>"), "Hello world");
});

test("sleep resolves early when aborted", async () => {
  const ac = new AbortController();
  const t0 = Date.now();
  setTimeout(() => ac.abort(), 20);
  await sleep(5000, ac.signal);
  assert.ok(Date.now() - t0 < 1000);
});
