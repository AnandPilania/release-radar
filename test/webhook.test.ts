import test from "node:test";
import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { once } from "node:events";
import type { AddressInfo } from "node:net";
import { startWebhook, toItem, verifySignature } from "../src/webhook.js";
import { canonGithub } from "../src/util.js";
import type { Item } from "../src/types.js";

const KW = ["CVE-", "security", "RCE"];
const sign = (secret: string, body: string) => "sha256=" + createHmac("sha256", secret).update(body).digest("hex");

const releasePayload = (over: any = {}) => ({
  action: "published",
  repository: { full_name: "laravel/framework", html_url: "https://github.com/laravel/framework" },
  release: {
    id: 1,
    name: "v11.9.0",
    tag_name: "v11.9.0",
    body: "Fixes CVE-2026-0001 in the router",
    html_url: "https://github.com/laravel/framework/releases/tag/v11.9.0",
    published_at: "2026-06-01T10:00:00Z",
    draft: false,
    ...over,
  },
});

test("verifySignature accepts a valid signature only", () => {
  const body = Buffer.from('{"a":1}');
  const good = sign("s3cret", body.toString());
  assert.equal(verifySignature("s3cret", body, good), true);
  assert.equal(verifySignature("s3cret", Buffer.from('{"a":2}'), good), false, "tampered body");
  assert.equal(verifySignature("other", body, good), false, "wrong secret");
  assert.equal(verifySignature("s3cret", body, undefined), false, "missing header");
  assert.equal(verifySignature("s3cret", body, "sha1=abc"), false, "wrong scheme");
  assert.equal(verifySignature("s3cret", body, "sha256=zz"), false, "not hex");
  assert.equal(verifySignature("s3cret", body, "sha256=abcd"), false, "wrong length");
});

test("release event -> Item whose dedupe key matches the atom-feed URL", () => {
  const i = toItem("release", releasePayload(), KW)!;
  assert.equal(i.security, true);
  assert.equal(i.key, canonGithub("https://github.com/laravel/framework/releases/tag/v11.9.0"));
  assert.match(i.title, /laravel\/framework v11\.9\.0/);
});

test("drafts and non-publish actions are ignored", () => {
  assert.equal(toItem("release", releasePayload({ draft: true }), KW), null);
  assert.equal(toItem("release", { ...releasePayload(), action: "edited" }, KW), null);
  assert.equal(toItem("push", {}, KW), null);
});

test("repository_advisory -> always security, severity in title", () => {
  const i = toItem(
    "repository_advisory",
    {
      action: "published",
      repository: { full_name: "o/r", html_url: "https://github.com/o/r" },
      repository_advisory: { ghsa_id: "GHSA-xxxx", cve_id: "CVE-2026-9", summary: "Bad bug", severity: "high", html_url: "https://github.com/o/r/security/advisories/GHSA-xxxx" },
    },
    KW,
  )!;
  assert.equal(i.security, true);
  assert.equal(i.title, "CVE-2026-9 Bad bug [high]");
});

test("tag create event", () => {
  const i = toItem("create", { ref_type: "tag", ref: "v1.0.0", repository: { full_name: "o/r", html_url: "https://github.com/o/r" } }, KW)!;
  assert.equal(i.url, "https://github.com/o/r/releases/tag/v1.0.0");
  assert.equal(i.security, false);
});

test("HTTP server: auth, routing, ack, size cap", async () => {
  const got: Item[] = [];
  let resolveDelivered!: () => void;
  const delivered = new Promise<void>((r) => (resolveDelivered = r));
  const srv = startWebhook({
    port: 0,
    host: "127.0.0.1",
    secret: "s3cret",
    keywords: KW,
    onItem: async (i) => {
      got.push(i);
      resolveDelivered();
    },
  });
  await once(srv, "listening");
  const base = `http://127.0.0.1:${(srv.address() as AddressInfo).port}`;
  try {
    assert.equal((await fetch(`${base}/healthz`)).status, 200);
    assert.equal((await fetch(`${base}/nope`, { method: "POST" })).status, 404);

    const body = JSON.stringify(releasePayload());
    const post = (b: string, headers: Record<string, string>, path = "/webhook/github") =>
      fetch(base + path, { method: "POST", body: b, headers: { "content-type": "application/json", ...headers } });

    assert.equal((await post(body, {})).status, 401, "unsigned");
    assert.equal((await post(body, { "x-hub-signature-256": sign("wrong", body), "x-github-event": "release" })).status, 401, "bad signature");
    assert.equal(got.length, 0);

    const ping = await post("{}", { "x-hub-signature-256": sign("s3cret", "{}"), "x-github-event": "ping" }, "/webhook/github?x=1");
    assert.equal(ping.status, 200);
    assert.equal(await ping.text(), "pong");

    const ok = await post(body, { "x-hub-signature-256": sign("s3cret", body), "x-github-event": "release" });
    assert.equal(ok.status, 202);
    await delivered;
    assert.equal(got.length, 1);
    assert.equal(got[0].security, true);

    const big = "x".repeat(1_100_000);
    let status: number | string;
    try {
      status = (await post(big, { "x-hub-signature-256": sign("s3cret", big) })).status;
    } catch {
      status = "connection reset"; // server hung up on an oversize body: also acceptable
    }
    assert.ok(status === 413 || status === "connection reset", String(status));
  } finally {
    srv.close();
    srv.closeAllConnections();
  }
});
