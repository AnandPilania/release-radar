import test from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { buildNotifiers, post, render, slackEscape, waText } from "../src/notifiers.js";
import { item, withEnv } from "./helpers.js";

const CLEAN = {
  DRY_RUN: undefined, SLACK_WEBHOOK_URL: undefined, TELEGRAM_BOT_TOKEN: undefined, TELEGRAM_CHAT_ID: undefined,
  SMTP_HOST: undefined, MAIL_TO: undefined, WA_TOKEN: undefined, WA_PHONE_ID: undefined, WA_TO: undefined, WA_TEMPLATE: undefined,
};

async function server(handler: (n: number, res: http.ServerResponse) => void) {
  let n = 0;
  const srv = http.createServer((_q, res) => handler(++n, res)).listen(0, "127.0.0.1");
  await new Promise((r) => srv.once("listening", r));
  return { url: `http://127.0.0.1:${(srv.address() as AddressInfo).port}`, count: () => n, close: () => srv.close() };
}

test("slackEscape neutralises <!channel>, links and entities from untrusted text", () => {
  assert.equal(slackEscape("<!channel> a&b <https://x|y>"), "&lt;!channel&gt; a&amp;b &lt;https://x|y&gt;");
});

test("waText: no newlines / long space runs, capped at 900", () => {
  const out = waText("line1\n\nline2   \t  line3\n" + "x".repeat(2000));
  assert.ok(!/\n|\t/.test(out));
  assert.ok(!/ {2,}/.test(out));
  assert.ok(out.startsWith("line1 | line2 line3 | "));
  assert.equal(out.length, 900);
});

test("post: errors name the host only; secrets in the URL path never reach the message", async () => {
  const s = await server((_n, res) => res.writeHead(404).end("no_service"));
  try {
    await assert.rejects(post(`${s.url}/services/T000/B000/SLACKSECRET`, {}), (e: Error) => {
      assert.ok(!e.message.includes("SLACKSECRET"), e.message);
      assert.match(e.message, /HTTP 404/);
      return true;
    });
    assert.equal(s.count(), 1, "4xx other than 429 is not retried");
  } finally { s.close(); }
});

test("post: retries 429 then succeeds", async () => {
  const s = await server((n, res) => (n < 3 ? res.writeHead(429, { "retry-after": "0" }).end() : res.writeHead(200).end("ok")));
  try {
    await post(s.url, {}, {}, { baseMs: 1 });
    assert.equal(s.count(), 3);
  } finally { s.close(); }
});

test("post: gives up after the attempt limit on persistent 5xx", async () => {
  const s = await server((_n, res) => res.writeHead(503).end("down"));
  try {
    await assert.rejects(post(s.url, {}, {}, { attempts: 3, baseMs: 1 }), /HTTP 503/);
    assert.equal(s.count(), 3);
  } finally { s.close(); }
});

test("post: unreachable host error has no URL path", async () => {
  await assert.rejects(post("http://127.0.0.1:9/bot123:TOKEN/send", {}, {}, { attempts: 1 }), (e: Error) => {
    assert.ok(!e.message.includes("TOKEN"), e.message);
    return true;
  });
});

test("buildNotifiers: channels appear only when fully configured", async () => {
  assert.deepEqual(await withEnv(CLEAN, () => buildNotifiers().map((n) => n.name)), []);
  assert.deepEqual(await withEnv({ ...CLEAN, SLACK_WEBHOOK_URL: "https://hooks.slack.com/x" }, () => buildNotifiers().map((n) => n.name)), ["slack"]);
  assert.deepEqual(await withEnv({ ...CLEAN, TELEGRAM_BOT_TOKEN: "t" }, () => buildNotifiers().map((n) => n.name)), [], "token without chat id");
  assert.deepEqual(await withEnv({ ...CLEAN, SMTP_HOST: "smtp.x" }, () => buildNotifiers().map((n) => n.name)), [], "smtp host without MAIL_TO");
  assert.deepEqual(
    await withEnv({ ...CLEAN, SLACK_WEBHOOK_URL: "u", TELEGRAM_BOT_TOKEN: "t", TELEGRAM_CHAT_ID: "1", SMTP_HOST: "h", MAIL_TO: "a@b", WA_TOKEN: "t", WA_PHONE_ID: "p", WA_TO: "9", WA_TEMPLATE: "tpl" }, () => buildNotifiers().map((n) => n.name)),
    ["slack", "telegram", "email", "whatsapp"],
  );
});

test("DRY_RUN=0 / false / off does NOT enable dry mode; 1 does", async () => {
  for (const v of ["0", "false", "off", ""]) assert.deepEqual(await withEnv({ ...CLEAN, DRY_RUN: v }, () => buildNotifiers().map((n) => n.name)), [], `DRY_RUN=${v}`);
  assert.deepEqual(await withEnv({ ...CLEAN, DRY_RUN: "1" }, () => buildNotifiers().map((n) => n.name)), ["console"]);
});

test("WhatsApp request: pinned-by-env API version, single sanitised body parameter, bearer auth", async () => {
  const seen: any[] = [];
  const s = await server((_n, res) => res.writeHead(200).end("{}"));
  const real = globalThis.fetch;
  globalThis.fetch = (async (u: any, init: any) => (seen.push({ u: String(u), init }), real(`${s.url}/x`, init))) as typeof fetch;
  try {
    await withEnv({ ...CLEAN, WA_TOKEN: "TOK", WA_PHONE_ID: "123", WA_TO: "919999999999", WA_TEMPLATE: "release_alert", WA_API_VERSION: "v99.0" }, async () => {
      await buildNotifiers()[0].send(item(), "a\nb");
    });
    assert.equal(seen[0].u, "https://graph.facebook.com/v99.0/123/messages");
    assert.equal(seen[0].init.headers.authorization, "Bearer TOK");
    const body = JSON.parse(seen[0].init.body);
    assert.equal(body.template.components[0].parameters[0].text, "a | b");
  } finally { globalThis.fetch = real; s.close(); }
});

test("render: labels, URL, and a bad DISPLAY_TZ must not throw", async () => {
  const sec = render(item({ security: true, source: "CISA KEV", url: "https://nvd.nist.gov/x" }));
  assert.match(sec, /^🚨 SECURITY \| CISA KEV/);
  assert.match(sec, /https:\/\/nvd\.nist\.gov\/x$/);
  assert.match(render(item()), /^📦 RELEASE/);
  await withEnv({ DISPLAY_TZ: "Not/AZone" }, () => assert.doesNotThrow(() => render(item({ publishedAt: "2026-06-01T10:00:00.000Z" }))));
});
