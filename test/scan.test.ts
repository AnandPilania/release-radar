import test from "node:test";
import assert from "node:assert/strict";
import { cvss3Score, meets, severityOf } from "../src/scan/cvss.js";
import { rangeFloor, readProject } from "../src/scan/manifests.js";
import { cmpVersion } from "../src/scan/osv.js";
import { scan, toAlert } from "../src/scan/scan.js";
import { renderText, toJson } from "../src/scan/report.js";
import { COMPOSER_PROJECT, fakeOsv, makeProject, NPM_PROJECT, withEnv } from "./helpers.js";

test("CVSS v3 base scores match the spec's well-known examples", () => {
  assert.equal(cvss3Score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), 9.8);
  assert.equal(cvss3Score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"), 10);
  assert.equal(cvss3Score("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"), 6.1);
  assert.equal(cvss3Score("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"), 5.5);
  assert.equal(cvss3Score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"), 0);
  assert.equal(cvss3Score("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"), undefined);
  assert.equal(cvss3Score("garbage"), undefined);
});

test("severity: GitHub label wins, else computed from CVSS, else unknown (which is never filtered out)", () => {
  assert.equal(severityOf({ database_specific: { severity: "MODERATE" } }).severity, "moderate");
  assert.equal(severityOf({ database_specific: { severity: "CRITICAL" }, severity: [{ type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" }] }).severity, "critical");
  assert.deepEqual(severityOf({ severity: [{ type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" }] }), { severity: "critical", score: 9.8 });
  assert.equal(severityOf({}).severity, "unknown");
  assert.equal(meets("unknown", "critical"), true);
  assert.equal(meets("moderate", "high"), false);
  assert.equal(meets("high", "high"), true);
});

test("rangeFloor and cmpVersion", () => {
  const f = rangeFloor;
  assert.equal(f("^4.5.0"), "4.5.0");
  assert.equal(f("~1.2"), "1.2.0");
  assert.equal(f(">=8.2 <9"), "8.2.0");
  assert.equal(f("11.*"), "11.0.0");
  assert.equal(f("^1 || ^2"), "1.0.0");
  assert.equal(f("1.0.0-beta.2"), "1.0.0-beta.2");
  for (const bad of ["*", "latest", "github:a/b", "a/b", "dev-main", "file:../x", "git+https://x/y.git", "workspace:*", ""]) assert.equal(f(bad), undefined, bad);
  assert.ok(cmpVersion("4.17.21", "4.17.20") > 0);
  assert.ok(cmpVersion("v1.10.0", "1.9.9") > 0);
  assert.equal(cmpVersion("1.0", "1.0.0"), 0);
});

test("readProject: npm lockfile gives exact versions, direct/dev flags, skips links", async () => {
  const p = await readProject(await makeProject(NPM_PROJECT));
  assert.equal(p.name, "demo-app");
  assert.deepEqual(p.manifests, ["package.json", "package-lock.json"]);
  const by = Object.fromEntries(p.deps.map((d) => [d.name, d]));
  assert.equal(by.lodash.version, "4.17.20");
  assert.equal(by.lodash.direct, true);
  assert.equal(by.qs.direct, false, "transitive");
  assert.equal(by.mocha.dev, true);
  assert.equal(by.express.dev, false);
  assert.ok(!by.mylink, "symlinked/workspace package skipped");
  assert.equal(p.notes.length, 0);
});

test("readProject: lockfile v1 (nested dependencies) is supported", async () => {
  const p = await readProject(await makeProject({
    "package.json": { name: "old", dependencies: { a: "^1.0.0" } },
    "package-lock.json": { lockfileVersion: 1, dependencies: { a: { version: "1.2.3", dependencies: { b: { version: "0.9.0", dev: false } } } } },
  }));
  assert.deepEqual(p.deps.map((d) => `${d.name}@${d.version}`).sort(), ["a@1.2.3", "b@0.9.0"]);
});

test("readProject: composer.lock normalises names/versions and skips platform + dev-branch entries", async () => {
  const p = await readProject(await makeProject(COMPOSER_PROJECT));
  assert.equal(p.name, "acme/shop");
  const by = Object.fromEntries(p.deps.map((d) => [d.name, d]));
  assert.equal(by["laravel/framework"].version, "11.9.0", "leading v stripped");
  assert.equal(by["laravel/framework"].direct, true);
  assert.equal(by["symfony/http-foundation"].direct, false);
  assert.equal(by["phpunit/phpunit"].dev, true);
  assert.ok(!by["vendor/branch"], "dev-main can't be matched to advisories");
  assert.ok(!Object.keys(by).some((n) => n === "php" || n.startsWith("ext-")));
});

test("readProject: no lockfile falls back to installed version, then range floor, and says so", async () => {
  const p = await readProject(await makeProject({
    "package.json": { name: "nolock", dependencies: { lodash: "^4.17.0", "left-pad": "^1.0.0", fancy: "github:foo/bar" } },
    "node_modules/lodash/package.json": { name: "lodash", version: "4.17.20" },
  }));
  const by = Object.fromEntries(p.deps.map((d) => [d.name, d]));
  assert.deepEqual([by.lodash.version, by.lodash.source], ["4.17.20", "installed"]);
  assert.deepEqual([by["left-pad"].version, by["left-pad"].source], ["1.0.0", "declared-range"]);
  assert.ok(!by.fancy);
  const notes = p.notes.join("\n");
  assert.match(notes, /No package-lock\.json/);
  assert.match(notes, /Skipped fancy@github:foo\/bar/);
  assert.match(notes, /lowest version/);
});

test("readProject: errors when nothing to read or invalid JSON", async () => {
  await assert.rejects(readProject(await makeProject({ "README.md": "hi" })), /No supported dependency files found/);
  await assert.rejects(readProject(await makeProject({ "package.json": "{oops" })), /package\.json is not valid JSON/);
});

test("scan: finds, ranks and explains vulnerabilities across npm AND composer in one project", async () => {
  const osv = await fakeOsv();
  try {
    await withEnv({ OSV_API_URL: osv.url }, async () => {
      const r = await scan(await makeProject({ ...NPM_PROJECT, ...COMPOSER_PROJECT }));
      assert.deepEqual(r.project.manifests, ["package.json", "package-lock.json", "composer.json", "composer.lock"]);
      assert.deepEqual(r.checked, { npm: 4, Packagist: 3 });
      assert.deepEqual(r.findings.map((f) => `${f.severity} ${f.dep.name}`), [
        "critical qs", "high lodash", "high phpunit/phpunit", "moderate laravel/framework", "low lodash",
      ]);
      const lodash = r.findings.find((f) => f.id === "GHSA-aaaa-lodash")!;
      assert.equal(lodash.upgradeTo, "4.17.21");
      assert.deepEqual(lodash.aliases, ["CVE-2021-23337"]);
      const qs = r.findings.find((f) => f.dep.name === "qs")!;
      assert.equal(qs.score, 9.8);
      assert.equal(qs.dep.direct, false);
      assert.equal(qs.upgradeTo, "6.5.3");
      assert.ok(!r.findings.some((f) => f.id === "GHSA-eeee-mocha"), "withdrawn advisory excluded");
      assert.ok(osv.requests.some((q) => q.body?.queries?.[0]?.page_token === "p2") || osv.requests.some((q) => q.body?.queries?.some((x: any) => x.page_token)), "followed pagination");
      assert.deepEqual(r.counts, { critical: 1, high: 2, moderate: 1, low: 1, unknown: 0 });
    });
  } finally { osv.close(); }
});

test("scan options: --min-severity, --prod and --ignore (by id or CVE alias)", async () => {
  const osv = await fakeOsv();
  try {
    await withEnv({ OSV_API_URL: osv.url }, async () => {
      const dir = await makeProject({ ...NPM_PROJECT, ...COMPOSER_PROJECT });
      const high = await scan(dir, { minSeverity: "high" });
      assert.deepEqual(high.findings.map((f) => f.severity), ["critical", "high", "high"]);

      const prod = await scan(dir, { prodOnly: true });
      assert.ok(!prod.findings.some((f) => f.dep.name === "phpunit/phpunit"), "dev-only package skipped");
      assert.deepEqual(prod.checked, { npm: 3, Packagist: 2 });

      const ign = await scan(dir, { ignore: ["cve-2021-23337", "GHSA-bbbb-qs"] });
      assert.ok(!ign.findings.some((f) => f.id === "GHSA-aaaa-lodash" || f.id === "GHSA-bbbb-qs"));
      assert.equal(ign.findings.length, 3);
    });
  } finally { osv.close(); }
});

test("scan: a clean project reports nothing; requests only exact name+ecosystem+version", async () => {
  const osv = await fakeOsv();
  try {
    await withEnv({ OSV_API_URL: osv.url }, async () => {
      const r = await scan(await makeProject({ "package.json": { name: "ok", dependencies: { safe: "^1" } }, "package-lock.json": { lockfileVersion: 3, packages: { "node_modules/safe": { version: "1.0.0" } } } }));
      assert.equal(r.findings.length, 0);
      assert.deepEqual(osv.requests[0].body.queries, [{ package: { name: "safe", ecosystem: "npm" }, version: "1.0.0" }]);
      assert.match(renderText(r), /No known vulnerabilities found\./);
    });
  } finally { osv.close(); }
});

test("OSV unreachable gives a clear error; a 4xx is not retried", async () => {
  await withEnv({ OSV_API_URL: "http://127.0.0.1:9" }, async () => {
    await assert.rejects(scan(await makeProject(NPM_PROJECT)), /Cannot reach OSV/);
  });
});

test("report: text names package, ids, fix and link; JSON is complete; alert is ONE message", async () => {
  const osv = await fakeOsv();
  try {
    await withEnv({ OSV_API_URL: osv.url }, async () => {
      const r = await scan(await makeProject({ ...NPM_PROJECT, ...COMPOSER_PROJECT }));
      const text = renderText(r);
      assert.match(text, /CRITICAL\s+qs@6\.5\.0 {2}\(transitive, prod\)/);
      assert.match(text, /GHSA-aaaa-lodash \/ CVE-2021-23337/);
      assert.match(text, /Fix: upgrade to 4\.17\.21 or later/);
      assert.match(text, /https:\/\/osv\.dev\/vulnerability\/GHSA-bbbb-qs/);
      assert.match(text, /demo-app: 5 known vulnerabilities \(1 critical, 2 high, 1 moderate, 1 low\)/);

      const j = toJson(r);
      assert.equal(j.vulnerabilities.length, 5);
      assert.deepEqual(Object.keys(j.vulnerabilities[0]).sort(), ["aliases", "direct", "dev", "ecosystem", "fixedIn", "id", "package", "score", "severity", "summary", "upgradeTo", "url", "version", "versionSource"].sort());

      const a = toAlert(r);
      assert.equal(a.security, true);
      assert.match(a.title, /demo-app has 5 known vulnerabilities/);
      assert.equal(a.summary!.split("\n").length, 5, "5 findings listed, none truncated, no \"+N more\" line");
      assert.match(a.summary!, /^CRITICAL qs@6\.5\.0/);
    });
  } finally { osv.close(); }
});
