import test from "node:test";
import assert from "node:assert/strict";
import { simpleParser } from "mailparser";
import { authenticated, mailToItem } from "../src/mail.js";
import { canonGithub } from "../src/util.js";
import type { MailRule } from "../src/types.js";

const KW = ["CVE-", "security", "RCE"];
const parse = (headers: string[], body: string) => simpleParser(Buffer.from(headers.join("\r\n") + "\r\n\r\n" + body));

const GH_AUTH = "Authentication-Results: mx.example.net; dkim=pass header.i=@github.com header.s=pf2023; spf=pass smtp.mailfrom=github.com; dmarc=pass (p=NONE) header.from=github.com";
const ghMail = (extra: string[] = []) =>
  parse(
    [
      "From: GitHub <notifications@github.com>",
      "To: radar@example.net",
      "Subject: [laravel/framework] Release v11.9.0 - Router fixes",
      "Message-ID: <rel-1@github.com>",
      "Date: Mon, 01 Jun 2026 10:00:00 +0000",
      "Content-Type: text/plain; charset=utf-8",
      ...extra,
    ],
    "A new release is out:\r\nhttps://github.com/laravel/framework/releases/tag/v11.9.0\r\n\r\nFixes CVE-2026-0001.",
  );

const RULES: MailRule[] = [
  { name: "GitHub watch", from: "notifications@github.com", subjectContains: "Release", notify: "all" },
  { name: "oss-security", listId: "oss-security", notify: "all" },
];

test("GitHub release mail -> Item with the same dedupe key as the releases.atom entry", async () => {
  const hit = mailToItem(await ghMail(), RULES, KW)!;
  assert.equal(hit.item.source, "GitHub watch");
  assert.equal(hit.item.key, canonGithub("https://github.com/laravel/framework/releases/tag/v11.9.0"));
  assert.equal(hit.item.url, "https://github.com/laravel/framework/releases/tag/v11.9.0");
  assert.equal(hit.item.security, true);
  assert.equal(hit.notify, "all");
});

test("mail that matches no rule is ignored", async () => {
  const m = await parse(["From: someone@example.com", "Subject: hello", "Message-ID: <x@y>"], "hi");
  assert.equal(mailToItem(m, RULES, KW), null);
});

test("List-Id rule matches mailing-list mail", async () => {
  const m = await parse(
    ["From: Alice <alice@example.org>", "Subject: [oss-security] Heap overflow in foo", "List-Id: <oss-security.lists.openwall.com>", "Message-ID: <m1@list>"],
    "Details at https://example.org/advisory",
  );
  const hit = mailToItem(m, RULES, KW)!;
  assert.equal(hit.item.source, "oss-security");
  assert.equal(hit.item.url, "https://example.org/advisory");
  assert.match(hit.item.key!, /^mail:/);
});

test("requireAuth: genuine mail passes, spoofed or unauthenticated mail is dropped", async () => {
  const strict: MailRule[] = [{ ...RULES[0], requireAuth: true }];
  const quiet = (fn: () => void) => {
    const e = console.error;
    console.error = () => {};
    try { fn(); } finally { console.error = e; }
  };

  assert.ok(mailToItem(await ghMail([GH_AUTH]), strict, KW), "dmarc=pass accepted");

  const noHeader = await ghMail();
  quiet(() => assert.equal(mailToItem(noHeader, strict, KW), null, "no Authentication-Results"));

  // attacker's own domain signs fine, but it isn't github.com
  const spoof = await ghMail(["Authentication-Results: mx.example.net; dkim=pass header.i=@evil.test; spf=pass smtp.mailfrom=evil.test; dmarc=fail header.from=github.com"]);
  assert.equal(authenticated(spoof), false);
  quiet(() => assert.equal(mailToItem(spoof, strict, KW), null));
});

test("authenticated(): aligned DKIM subdomain ok; forged lower header cannot override ours", async () => {
  const dkimOnly = await ghMail(["Authentication-Results: mx.example.net; dkim=pass header.d=mail.github.com; spf=none"]);
  assert.equal(authenticated(dkimOnly), true);

  // Our server's header is on top (fail); a forged 'pass' added by the sender sits below it.
  const forged = await parse(
    [
      "Authentication-Results: mx.example.net; dkim=fail; dmarc=fail header.from=github.com",
      "Authentication-Results: forged.example; dmarc=pass header.from=github.com",
      "From: GitHub <notifications@github.com>",
      "Subject: Release x",
      "Message-ID: <f@x>",
    ],
    "body",
  );
  assert.equal(authenticated(forged), false);
});
