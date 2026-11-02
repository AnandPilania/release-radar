import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Item, Notifier } from "../src/types.js";

export const tmpState = async () => join(await mkdtemp(join(tmpdir(), "rr-")), "state.json");

/** Run fn with env vars set (undefined = unset), restoring afterwards. */
export async function withEnv<T>(vars: Record<string, string | undefined>, fn: () => Promise<T> | T): Promise<T> {
  const old: Record<string, string | undefined> = {};
  for (const [k, v] of Object.entries(vars)) {
    old[k] = process.env[k];
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
  try {
    return await fn();
  } finally {
    for (const [k, v] of Object.entries(old)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  }
}

export const item = (o: Partial<Item> = {}): Item => ({
  id: "i1",
  source: "src",
  title: "title",
  url: "https://example.com/1",
  detectedAt: "2026-06-01T10:00:00.000Z",
  security: false,
  ...o,
});

export function recorder(): Notifier & { sent: Item[] } {
  const sent: Item[] = [];
  return { name: "rec", sent, send: async (i) => void sent.push(i) };
}
export const failing = (name = "bad"): Notifier => ({
  name,
  send: async () => {
    throw new Error("boom");
  },
});

export const atom = (entries: { id: string; title: string; href: string; updated: string; summary?: string }[]) =>
  `<?xml version="1.0"?><feed xmlns="http://www.w3.org/2005/Atom">${entries
    .map(
      (e) =>
        `<entry><id>${e.id}</id><title>${e.title}</title><link rel="alternate" href="${e.href}"/><link rel="self" href="https://x/self"/><updated>${e.updated}</updated><summary>${e.summary ?? ""}</summary></entry>`,
    )
    .join("")}</feed>`;

/** Replace global fetch for one test. Handler gets (url, init). */
export function stubFetch(handler: (url: string, init: RequestInit) => Response | Promise<Response>) {
  const real = globalThis.fetch;
  const calls: { url: string; headers: Record<string, string> }[] = [];
  globalThis.fetch = (async (url: any, init: RequestInit = {}) => {
    calls.push({ url: String(url), headers: (init.headers ?? {}) as Record<string, string> });
    return handler(String(url), init);
  }) as typeof fetch;
  return { calls, restore: () => void (globalThis.fetch = real) };
}

import http from "node:http";
import type { AddressInfo } from "node:net";
import { mkdir, writeFile } from "node:fs/promises";
import { dirname } from "node:path";

/** Write a project tree into a temp dir. Object values are JSON-stringified. */
export async function makeProject(files: Record<string, unknown>): Promise<string> {
  const root = dirname(await tmpState());
  for (const [rel, content] of Object.entries(files)) {
    const f = join(root, rel);
    await mkdir(dirname(f), { recursive: true });
    await writeFile(f, typeof content === "string" ? content : JSON.stringify(content, null, 2));
  }
  return root;
}

const aff = (name: string, ecosystem: string, ...fixed: string[]) => [
  { package: { name, ecosystem }, ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, ...fixed.map((f) => ({ fixed: f }))] }] },
];

export const ADVISORIES: Record<string, any> = {
  "GHSA-aaaa-lodash": { id: "GHSA-aaaa-lodash", aliases: ["CVE-2021-23337"], summary: "Command injection in lodash template", database_specific: { severity: "HIGH" }, affected: aff("lodash", "npm", "4.17.21") },
  "GHSA-dddd-lodash": { id: "GHSA-dddd-lodash", aliases: [], summary: "Minor lodash ReDoS", database_specific: { severity: "LOW" }, affected: aff("lodash", "npm", "4.17.22") },
  "GHSA-bbbb-qs": { id: "GHSA-bbbb-qs", aliases: ["CVE-2022-24999"], summary: "qs prototype pollution", severity: [{ type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" }], affected: aff("qs", "npm", "6.5.3", "6.7.3") },
  "GHSA-cccc-laravel": { id: "GHSA-cccc-laravel", aliases: ["CVE-2026-1111"], summary: "Laravel encrypter flaw", database_specific: { severity: "MODERATE" }, affected: aff("laravel/framework", "Packagist", "11.10.0") },
  "GHSA-eeee-mocha": { id: "GHSA-eeee-mocha", aliases: [], summary: "Withdrawn advisory", withdrawn: "2026-01-01T00:00:00Z", affected: aff("mocha", "npm", "10.0.1") },
  "GHSA-ffff-phpunit": { id: "GHSA-ffff-phpunit", aliases: [], summary: "phpunit dev-only issue", database_specific: { severity: "HIGH" }, affected: aff("phpunit/phpunit", "Packagist", "10.5.1") },
};
/** package@version -> advisory ids (lodash has TWO pages to exercise pagination). */
export const HITS: Record<string, string[]> = {
  "npm:lodash@4.17.20": ["GHSA-aaaa-lodash", "GHSA-dddd-lodash"],
  "npm:qs@6.5.0": ["GHSA-bbbb-qs"],
  "Packagist:laravel/framework@11.9.0": ["GHSA-cccc-laravel"],
  "npm:mocha@10.0.0": ["GHSA-eeee-mocha"],
  "Packagist:phpunit/phpunit@10.5.0": ["GHSA-ffff-phpunit"],
};

/** A local stand-in for api.osv.dev (same endpoints and response shapes). */
export async function fakeOsv() {
  const requests: { path: string; body?: any }[] = [];
  const srv = http.createServer((req, res) => {
    let raw = "";
    req.on("data", (c) => (raw += c));
    req.on("end", () => {
      const body = raw ? JSON.parse(raw) : undefined;
      requests.push({ path: req.url!, body });
      const send = (code: number, data: unknown) => res.writeHead(code, { "content-type": "application/json" }).end(JSON.stringify(data));
      if (req.url === "/v1/querybatch") {
        return send(200, {
          results: body.queries.map((q: any) => {
            const ids = HITS[`${q.package.ecosystem}:${q.package.name}@${q.version}`] ?? [];
            if (!ids.length) return {};
            if (ids.length > 1 && !q.page_token) return { vulns: [{ id: ids[0], modified: "x" }], next_page_token: "p2" };
            return { vulns: (q.page_token ? ids.slice(1) : ids).map((id) => ({ id, modified: "x" })) };
          }),
        });
      }
      const m = req.url!.match(/^\/v1\/vulns\/(.+)$/);
      if (m && ADVISORIES[decodeURIComponent(m[1])]) return send(200, ADVISORIES[decodeURIComponent(m[1])]);
      send(404, { code: 5, message: "Bug not found" });
    });
  }).listen(0, "127.0.0.1");
  await new Promise((r) => srv.once("listening", r));
  return { url: `http://127.0.0.1:${(srv.address() as AddressInfo).port}`, requests, close: () => srv.close() };
}

export const NPM_PROJECT = {
  "package.json": { name: "demo-app", dependencies: { lodash: "^4.17.0", express: "^4.18.0" }, devDependencies: { mocha: "^10.0.0" } },
  "package-lock.json": {
    lockfileVersion: 3,
    packages: {
      "": { name: "demo-app" },
      "node_modules/lodash": { version: "4.17.20" },
      "node_modules/express": { version: "4.18.0" },
      "node_modules/qs": { version: "6.5.0" },
      "node_modules/mocha": { version: "10.0.0", dev: true },
      "node_modules/mylink": { resolved: "../mylink", link: true },
    },
  },
};
export const COMPOSER_PROJECT = {
  "composer.json": { name: "acme/shop", require: { php: "^8.2", "ext-json": "*", "laravel/framework": "^11.0" }, "require-dev": { "phpunit/phpunit": "^10.5" } },
  "composer.lock": {
    packages: [{ name: "laravel/framework", version: "v11.9.0" }, { name: "symfony/http-foundation", version: "v7.0.1" }, { name: "vendor/branch", version: "dev-main" }],
    "packages-dev": [{ name: "phpunit/phpunit", version: "10.5.0" }],
  },
};
