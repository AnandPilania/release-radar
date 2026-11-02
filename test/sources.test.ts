import test from "node:test";
import assert from "node:assert/strict";
import { fetchSource, parseSource, poll } from "../src/sources.js";
import type { SourceCfg } from "../src/types.js";
import type { State } from "../src/store.js";
import { atom, stubFetch } from "./helpers.js";

const KW = ["CVE-", "security", "RCE"];
const feed: SourceCfg = { name: "Feed", type: "feed", url: "https://example.com/feed.atom", notify: "all" };
const kev: SourceCfg = { name: "KEV", type: "kev", url: "https://example.com/kev.json", notify: "all" };
const fresh = (): State => ({ seen: {}, http: {}, baselined: [] });

test("parses Atom: picks the non-self link, strips HTML, flags security", () => {
  const body = atom([
    { id: "tag:1", title: "Laravel v11.9.0", href: "https://github.com/laravel/framework/releases/tag/v11.9.0", updated: "2026-06-01T10:00:00Z", summary: "&lt;p&gt;Fixes CVE-2026-1&lt;/p&gt;" },
    { id: "tag:2", title: "Laravel v11.8.0", href: "https://github.com/laravel/framework/releases/tag/v11.8.0", updated: "2026-05-01T10:00:00Z" },
  ]);
  const items = parseSource(feed, body, KW, "2026-06-01T10:00:05.000Z");
  assert.equal(items.length, 2);
  assert.equal(items[0].url, "https://github.com/laravel/framework/releases/tag/v11.9.0");
  assert.equal(items[0].security, true);
  assert.equal(items[1].security, false);
  assert.equal(items[0].publishedAt, "2026-06-01T10:00:00.000Z");
  assert.equal(items[0].id, "Feed:tag:1");
});

test("parses RSS 2.0 (guid, pubDate, single item)", () => {
  const rss = `<rss version="2.0"><channel><item><title>PHP 8.4.9 released</title><link>https://php.net/8.4.9</link><guid isPermaLink="false">php-849</guid><pubDate>Tue, 02 Jun 2026 09:00:00 GMT</pubDate><description>Security fix</description></item></channel></rss>`;
  const [i] = parseSource(feed, rss, KW);
  assert.equal(i.id, "Feed:php-849");
  assert.equal(i.url, "https://php.net/8.4.9");
  assert.equal(i.security, true);
  assert.equal(i.publishedAt, "2026-06-02T09:00:00.000Z");
});

test("parses CISA KEV and always marks security", () => {
  const body = JSON.stringify({ vulnerabilities: [{ cveID: "CVE-2026-1", vendorProject: "Acme", product: "Widget", shortDescription: "RCE", dateAdded: "2026-06-01" }] });
  const [i] = parseSource(kev, body, KW);
  assert.equal(i.security, true);
  assert.equal(i.url, "https://nvd.nist.gov/vuln/detail/CVE-2026-1");
  assert.match(i.title, /CVE-2026-1 actively exploited: Acme Widget/);
});

test("a 200 that is not a feed is an ERROR, not 'zero new items'", () => {
  assert.throws(() => parseSource(feed, "<html><body>Please log in to the wifi</body></html>", KW), /not an Atom\/RSS/);
  assert.throws(() => parseSource(kev, JSON.stringify({ oops: true }), KW), /unexpected KEV JSON/);
});

test("conditional GET: sends validators, 304 yields nothing", async () => {
  const body = atom([{ id: "1", title: "t", href: "https://x/1", updated: "2026-06-01T00:00:00Z" }]);
  const s = stubFetch((_u, init) =>
    (init.headers as any)["if-none-match"] === '"v1"'
      ? new Response(null, { status: 304 })
      : new Response(body, { status: 200, headers: { etag: '"v1"', "last-modified": "Mon, 01 Jun 2026 00:00:00 GMT" } }),
  );
  try {
    const state = fresh();
    assert.equal((await poll(feed, state, KW)).length, 1);
    assert.equal(state.http[feed.url].etag, '"v1"');
    assert.equal((await poll(feed, state, KW)).length, 0);
    assert.equal(s.calls[1].headers["if-none-match"], '"v1"');
    assert.equal(s.calls[1].headers["if-modified-since"], "Mon, 01 Jun 2026 00:00:00 GMT");
  } finally {
    s.restore();
  }
});

test("a response that fails to parse must NOT poison the ETag cache", async () => {
  const s = stubFetch(() => new Response("<html>captive portal</html>", { status: 200, headers: { etag: '"bad"' } }));
  try {
    const state = fresh();
    await assert.rejects(poll(feed, state, KW), /not an Atom\/RSS/);
    assert.deepEqual(state.http, {}, "cache must stay empty so the next poll refetches");
  } finally {
    s.restore();
  }
});

test("HTTP errors surface with the source name", async () => {
  const s = stubFetch(() => new Response("nope", { status: 503 }));
  try {
    await assert.rejects(fetchSource(feed, fresh()), /Feed: HTTP 503/);
  } finally {
    s.restore();
  }
});
