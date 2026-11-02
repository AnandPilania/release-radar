import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { readProject, type Dep } from "../src/scan/manifests.js";
import { cmpVersion } from "../src/scan/osv.js";
import { scan, type ScanResult } from "../src/scan/scan.js";
import { renderHtml, renderText, toJson, TAILWIND_CDN } from "../src/scan/report.js";
import { fakeOsv, makeProject, NPM_PROJECT, withEnv } from "./helpers.js";

const byName = (deps: Dep[]) => Object.fromEntries(deps.map((d) => [d.name, d]));
const PKG = { name: "demo", dependencies: { a: "^1.0.0" }, devDependencies: { d: "^2.0.0" } };

// ---------------------------------------------------------------- yarn / pnpm

test("yarn.lock v1: exact versions, transitive deps, prod vs dev by reachability, git deps reported", async () => {
  const lock = `# yarn lockfile v1


"@scope/b@^1.1.0":
  version "1.1.5"
  resolved "https://registry.yarnpkg.com/@scope/b/-/b-1.1.5.tgz#abc"
  dependencies:
    c "^3.0.0"

a@^1.0.0:
  version "1.2.0"
  dependencies:
    "@scope/b" "^1.1.0"

c@^3.0.0, c@^3.1.0:
  version "3.2.0"

d@^2.0.0:
  version "2.0.1"
  dependencies:
    c "^3.1.0"
    dd "^1.0.0"

dd@^1.0.0:
  version "1.0.0"

gitdep@github:foo/bar:
  version "0.0.1"
  resolved "https://codeload.github.com/foo/bar/tar.gz/abc"
`;
  const p = await readProject(await makeProject({ "package.json": PKG, "yarn.lock": lock }));
  assert.deepEqual(p.manifests, ["package.json", "yarn.lock"]);
  const by = byName(p.deps);
  assert.deepEqual([by.a.version, by.a.direct, by.a.dev], ["1.2.0", true, false]);
  assert.deepEqual([by["@scope/b"].version, by["@scope/b"].direct, by["@scope/b"].dev], ["1.1.5", false, false]);
  assert.deepEqual([by.c.direct, by.c.dev], [false, false], "reachable from a prod dependency => not dev, even though d also needs it");
  assert.deepEqual([by.d.direct, by.d.dev], [true, true]);
  assert.deepEqual([by.dd.direct, by.dd.dev], [false, true]);
  assert.ok(!by.gitdep);
  assert.match(p.notes.join("\n"), /NOT checked: gitdep@github:foo\/bar/);
  assert.equal(p.notes.filter((n) => /out of date/.test(n)).length, 0);
});

test("yarn.lock berry (v2+): resolution gives the real version; workspaces are skipped silently", async () => {
  const lock = `__metadata:
  version: 8
  cacheKey: 10c0

"a@npm:^1.0.0":
  version: 1.2.0
  resolution: "a@npm:1.2.0"
  dependencies:
    b: ^1.1.0
  languageName: node
  linkType: hard

"b@npm:^1.1.0, b@npm:^1.0.0":
  version: 1.1.5
  resolution: "b@npm:1.1.5"
  languageName: node
  linkType: hard

"d@npm:^2.0.0":
  version: 2.0.1
  resolution: "d@npm:2.0.1"
  dependencies:
    dd: ^1.0.0
  languageName: node
  linkType: hard

"dd@npm:^1.0.0":
  version: 1.0.0
  resolution: "dd@npm:1.0.0"
  languageName: node
  linkType: hard

"demo@workspace:.":
  version: 0.0.0-use.local
  resolution: "demo@workspace:."
  dependencies:
    a: ^1.0.0
    d: ^2.0.0
  languageName: unknown
  linkType: soft
`;
  const p = await readProject(await makeProject({ "package.json": PKG, "yarn.lock": lock }));
  const by = byName(p.deps);
  assert.deepEqual(Object.keys(by).sort(), ["a", "b", "d", "dd"]);
  assert.deepEqual([by.a.direct, by.a.dev, by.b.direct, by.b.dev, by.d.dev, by.dd.dev], [true, false, false, false, true, true]);
  assert.equal(p.notes.length, 0);
});

test("yarn.lock: npm aliases resolve to the real package", async () => {
  const lock = `# yarn lockfile v1\n\n\nfoo@npm:qs@^6.5.0:\n  version "6.5.0"\n`;
  const p = await readProject(await makeProject({ "package.json": { name: "x", dependencies: { foo: "npm:qs@^6.5.0" } }, "yarn.lock": lock }));
  assert.deepEqual(p.deps.map((d) => `${d.name}@${d.version}`), ["qs@6.5.0"]);
  assert.equal(p.notes.length, 0, "an alias is not reported as a stale lockfile");
});

test("pnpm-lock.yaml v9: importers + snapshots, peer-suffixed keys, non-registry tarballs reported", async () => {
  const lock = `lockfileVersion: '9.0'

importers:
  .:
    dependencies:
      a:
        specifier: ^1.0.0
        version: 1.2.0
    devDependencies:
      d:
        specifier: ^2.0.0
        version: 2.0.1(peer@1.0.0)

packages:
  a@1.2.0:
    resolution: {integrity: sha512-x}
  b@1.1.5:
    resolution: {integrity: sha512-x}
  d@2.0.1:
    resolution: {integrity: sha512-x}
  dd@1.0.0:
    resolution: {integrity: sha512-x}
  '@scope/e@1.0.0':
    resolution: {tarball: https://codeload.github.com/x/y/tar.gz/abc}

snapshots:
  a@1.2.0:
    dependencies:
      b: 1.1.5
  b@1.1.5: {}
  d@2.0.1(peer@1.0.0):
    dependencies:
      dd: 1.0.0
  dd@1.0.0: {}
  '@scope/e@1.0.0': {}
`;
  const p = await readProject(await makeProject({ "package.json": PKG, "pnpm-lock.yaml": lock }));
  assert.deepEqual(p.manifests, ["package.json", "pnpm-lock.yaml"]);
  const by = byName(p.deps);
  assert.deepEqual(Object.keys(by).sort(), ["a", "b", "d", "dd"]);
  assert.deepEqual([by.a.direct, by.a.dev, by.b.direct, by.b.dev], [true, false, false, false]);
  assert.deepEqual([by.d.direct, by.d.dev, by.dd.direct, by.dd.dev], [true, true, false, true]);
  assert.match(p.notes.join("\n"), /@scope\/e@1\.0\.0/);
});

test("pnpm-lock.yaml v5 and v6 key formats", async () => {
  const v5 = `lockfileVersion: 5.4
specifiers:
  a: ^1.0.0
  d: ^2.0.0
dependencies:
  a: 1.2.0
devDependencies:
  d: 2.0.1_peer@1.0.0
packages:
  /a/1.2.0:
    resolution: {integrity: sha512-x}
    dependencies:
      '@scope/b': 1.1.5
    dev: false
  /@scope/b/1.1.5:
    resolution: {integrity: sha512-x}
    dev: false
  /d/2.0.1_peer@1.0.0:
    resolution: {integrity: sha512-x}
    dev: true
`;
  const a = byName((await readProject(await makeProject({ "package.json": PKG, "pnpm-lock.yaml": v5 }))).deps);
  assert.deepEqual([a.a.version, a.a.direct, a["@scope/b"].version, a["@scope/b"].dev, a.d.version, a.d.dev], ["1.2.0", true, "1.1.5", false, "2.0.1", true]);

  const v6 = `lockfileVersion: '6.0'
dependencies:
  a:
    specifier: ^1.0.0
    version: 1.2.0
devDependencies:
  d:
    specifier: ^2.0.0
    version: 2.0.1(peer@1.0.0)
packages:
  /a@1.2.0:
    resolution: {integrity: sha512-x}
    dependencies:
      '@scope/b': 1.1.5
  /@scope/b@1.1.5:
    resolution: {integrity: sha512-x}
  /d@2.0.1(peer@1.0.0):
    resolution: {integrity: sha512-x}
`;
  const b = byName((await readProject(await makeProject({ "package.json": PKG, "pnpm-lock.yaml": v6 }))).deps);
  assert.deepEqual([b.a.version, b["@scope/b"].version, b["@scope/b"].dev, b.d.dev], ["1.2.0", "1.1.5", false, true]);
});

test("lockfile choice: packageManager wins, otherwise package-lock.json, and the ignored one is mentioned; a corrupt lock fails loudly", async () => {
  const yarnLock = `# yarn lockfile v1\n\n\nqs@^6.5.0:\n  version "6.5.0"\n`;
  const both = { ...NPM_PROJECT, "yarn.lock": yarnLock };
  const p1 = await readProject(await makeProject(both));
  assert.deepEqual(p1.manifests, ["package.json", "package-lock.json"]);
  assert.match(p1.notes.join("\n"), /Found yarn\.lock next to package-lock\.json; only package-lock\.json was checked/);

  const p2 = await readProject(await makeProject({ ...both, "package.json": { name: "demo-app", packageManager: "yarn@4.1.0", dependencies: { qs: "^6.5.0" } } }));
  assert.deepEqual(p2.manifests, ["package.json", "yarn.lock"]);

  await assert.rejects(readProject(await makeProject({ "package.json": PKG, "pnpm-lock.yaml": "lockfileVersion: [unclosed" })), /pnpm-lock\.yaml could not be parsed/);
});

// ---------------------------------------------------------------- Python / Rust

test("requirements.txt: exact pins only; everything else is counted, never guessed", async () => {
  const p = await readProject(await makeProject({
    "requirements.txt": `# deps
Django==3.2.0 \\
    --hash=sha256:abc
requests[security]==2.31.0 ; python_version >= "3.8"
Flask_SQLAlchemy==3.0.0  # inline comment
numpy>=1.20
git+https://github.com/x/y.git#egg=y
pkg==1.*
-r other.txt
-e .
`,
    "requirements-dev.txt": "pytest==8.0.0\n",
  }));
  assert.deepEqual(p.manifests, ["requirements.txt", "requirements-dev.txt"]);
  const by = byName(p.deps);
  assert.deepEqual(Object.keys(by).sort(), ["django", "flask-sqlalchemy", "pytest", "requests"]);
  assert.deepEqual([by.django.version, by.django.ecosystem, by.pytest.dev, by.django.dev], ["3.2.0", "PyPI", true, false]);
  assert.match(p.notes.join("\n"), /requirements\.txt: 3 lines are not an exact "==" pin/);
});

test("Pipfile.lock and poetry.lock", async () => {
  const p = await readProject(await makeProject({
    "Pipfile.lock": { default: { Django: { version: "==3.2.0" }, local: { path: "." } }, develop: { pytest: { version: "==8.0.0" } } },
    "requirements.txt": "django==3.2.0\n", // same package in a second file must not be reported twice
    "poetry.lock": `[[package]]
name = "Requests"
version = "2.31.0"
description = "x"
category = "main"

[package.dependencies]
urllib3 = ">=1.21"
name = "decoy"
version = "9.9.9"

[[package]]
name = "pytest"
version = "8.0.0"
category = "dev"

[[package]]
name = "gitpkg"
version = "0.1.0"

[package.source]
type = "git"
url = "https://github.com/x/y"
`,
  }));
  const names = p.deps.map((d) => `${d.name}@${d.version}${d.dev ? ":dev" : ""}`).sort();
  assert.deepEqual(names, ["django@3.2.0", "pytest@8.0.0:dev", "requests@2.31.0"], "pytest is in Pipfile.lock and poetry.lock: one entry");
  assert.match(p.notes.join("\n"), /1 Pipfile\.lock package/);
  assert.match(p.notes.join("\n"), /1 poetry\.lock package from git/);
  assert.ok(p.deps.every((d) => d.direct === undefined), "lockfiles that don't say direct/transitive are not guessed");
});

test("Cargo.lock: registry crates only; name comes from Cargo.toml", async () => {
  const p = await readProject(await makeProject({
    "Cargo.toml": `[package]\nname = "my-crate"\nversion = "0.1.0"\n`,
    "Cargo.lock": `version = 3

[[package]]
name = "my-crate"
version = "0.1.0"
dependencies = [
 "smallvec",
]

[[package]]
name = "smallvec"
version = "1.6.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "abc"

[[package]]
name = "fromgit"
version = "0.2.0"
source = "git+https://github.com/x/y#abc"
`,
  }));
  assert.equal(p.name, "my-crate");
  assert.deepEqual(p.deps.map((d) => `${d.ecosystem} ${d.name}@${d.version}`), ["crates.io smallvec@1.6.0"]);
  assert.match(p.notes.join("\n"), /1 Cargo\.lock package from git sources were NOT checked/);
});

test("scan: one project, four ecosystems; OSV gets the right ecosystem names", async () => {
  const osv = await fakeOsv();
  try {
    await withEnv({ OSV_API_URL: osv.url }, async () => {
      const dir = await makeProject({
        ...NPM_PROJECT,
        "requirements.txt": "django==3.2.0\n",
        "Cargo.lock": `[[package]]\nname = "smallvec"\nversion = "1.6.0"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n`,
      });
      const r = await scan(dir);
      assert.deepEqual(r.checked, { npm: 4, PyPI: 1, "crates.io": 1 });
      assert.deepEqual(r.findings.map((f) => `${f.severity} ${f.dep.ecosystem}:${f.dep.name}`), [
        "critical npm:qs", "critical crates.io:smallvec", "high PyPI:django", "high npm:lodash", "low npm:lodash",
      ]);
      assert.equal(r.findings.find((f) => f.dep.name === "django")!.upgradeTo, "3.2.5");
      assert.match(renderText(r), /Checked 4 npm \+ 1 PyPI \+ 1 crates\.io packages against OSV\.dev/);
      assert.equal(toJson(r).vulnerabilities.find((v) => v.package === "django")!.direct, null);
    });
  } finally { osv.close(); }
});

// ---------------------------------------------------------------- trust fixes

test("npm alias: the real package is queried, not the alias name", async () => {
  const osv = await fakeOsv();
  try {
    await withEnv({ OSV_API_URL: osv.url }, async () => {
      const dir = await makeProject({
        "package.json": { name: "al", dependencies: { "my-qs": "npm:qs@^6.5.0" } },
        "package-lock.json": { lockfileVersion: 3, packages: { "": {}, "node_modules/my-qs": { name: "qs", version: "6.5.0" } } },
      });
      const r = await scan(dir);
      assert.deepEqual(osv.requests[0].body.queries, [{ package: { name: "qs", ecosystem: "npm" }, version: "6.5.0" }]);
      assert.deepEqual(r.findings.map((f) => f.dep.name), ["qs"], "an alias used to hide a vulnerable package");
      assert.equal(r.findings[0].dep.direct, true);
      assert.equal(r.project.notes.length, 0, "alias is not reported as a stale lockfile");
    });
  } finally { osv.close(); }
});

test("npm: a nested copy of a declared package is transitive, not direct", async () => {
  const p = await readProject(await makeProject({
    "package.json": { name: "n", dependencies: { lodash: "^4.17.21" } },
    "package-lock.json": { lockfileVersion: 3, packages: {
      "": {},
      "node_modules/lodash": { version: "4.17.21" },
      "node_modules/other": { version: "1.0.0" },
      "node_modules/other/node_modules/lodash": { version: "4.17.20" },
    } },
  }));
  const l = p.deps.filter((d) => d.name === "lodash");
  assert.deepEqual(l.map((d) => [d.version, d.direct]).sort(), [["4.17.20", false], ["4.17.21", true]]);
});

test("npm lockfile: git/tarball entries are reported as unchecked instead of being silently dropped or mis-matched", async () => {
  const p = await readProject(await makeProject({
    "package.json": { name: "g", dependencies: { a: "^1.0.0", viagit: "github:x/y" } },
    "package-lock.json": { lockfileVersion: 3, packages: {
      "": {},
      "node_modules/a": { version: "1.0.0", resolved: "https://registry.npmjs.org/a/-/a-1.0.0.tgz" },
      "node_modules/viagit": { version: "2.0.0", resolved: "git+ssh://git@github.com/x/y.git#abc" },
    } },
  }));
  assert.deepEqual(p.deps.map((d) => d.name), ["a"]);
  assert.match(p.notes.join("\n"), /1 npm package from git, file or tarball sources.*viagit@2\.0\.0/);
});

test("composer: dev-branch packages are reported as unchecked", async () => {
  const p = await readProject(await makeProject({
    "composer.json": { name: "a/b", require: { "x/y": "dev-main" } },
    "composer.lock": { packages: [{ name: "x/y", version: "dev-main" }, { name: "p/q", version: "v1.0.0" }], "packages-dev": [] },
  }));
  assert.deepEqual(p.deps.map((d) => d.name), ["p/q"]);
  assert.match(p.notes.join("\n"), /pinned to a branch or commit.*x\/y@dev-main/);
});

test("cmpVersion: pre-releases sort before releases, .post after, numerics numerically", () => {
  const lt = (a: string, b: string) => assert.ok(cmpVersion(a, b) < 0, `${a} < ${b}`);
  lt("1.0.0-beta.1", "1.0.0");
  lt("1.0.0rc1", "1.0.0");
  lt("1.0.0-alpha", "1.0.0-beta");
  lt("1.0.0-beta.2", "1.0.0-beta.10");
  lt("1.0.0", "1.0.0.post1");
  lt("1.9.9", "1.10.0");
  assert.equal(cmpVersion("v2.0", "2.0.0"), 0);
});

test("filters never hide silently: ignored / below-severity / dev-skipped counts are tracked and shown", async () => {
  const osv = await fakeOsv();
  try {
    await withEnv({ OSV_API_URL: osv.url }, async () => {
      const r = await scan(await makeProject(NPM_PROJECT), { minSeverity: "critical", prodOnly: true, ignore: ["GHSA-aaaa-lodash"] });
      assert.deepEqual(r.hidden, { ignored: 1, belowSeverity: 1, devSkipped: 1 });
      assert.match(renderText(r), /Hidden by your options: 1 ignored by --ignore, 1 below --min-severity critical, 1 dev-only package skipped by --prod/);
      assert.match(renderHtml(r), /Hidden by your options: 1 ignored/);
      assert.deepEqual(toJson(r).hidden, r.hidden);
    });
  } finally { osv.close(); }
});

// ---------------------------------------------------------------- HTML report

test("html report: standalone page, pinned Tailwind CDN, findings, filters, coverage gaps", async () => {
  const osv = await fakeOsv();
  try {
    await withEnv({ OSV_API_URL: osv.url }, async () => {
      const r = await scan(await makeProject({ ...NPM_PROJECT, "yarn.lock": "# yarn lockfile v1\n" }));
      const html = renderHtml(r);
      assert.match(html, /^<!doctype html>/i);
      assert.ok(html.includes(`<script src="${TAILWIND_CDN}"></script>`));
      assert.match(TAILWIND_CDN, /cdn\.tailwindcss\.com\/\d+\.\d+\.\d+$/, "pinned to an exact version");
      assert.match(html, /<title>Dependency scan: demo-app<\/title>/);
      assert.match(html, /data-sev="critical"/);
      assert.match(html, /href="https:\/\/osv\.dev\/vulnerability\/GHSA-bbbb-qs"/);
      assert.match(html, /CVE-2021-23337/);
      assert.match(html, /Upgrade to <strong>4\.17\.21<\/strong>/);
      assert.match(html, /Coverage gaps in this scan/);
      assert.match(html, /only package-lock\.json was checked/);
      assert.match(html, /id="q"/);
      assert.equal((html.match(/<article data-finding/g) ?? []).length, r.findings.length);
    });
  } finally { osv.close(); }
});

test("html report: clean + complete scan says so; clean + partial scan does NOT claim a clean bill of health", async () => {
  const osv = await fakeOsv();
  try {
    await withEnv({ OSV_API_URL: osv.url }, async () => {
      const lock = { lockfileVersion: 3, packages: { "": {}, "node_modules/safe": { version: "1.0.0" } } };
      const full = renderHtml(await scan(await makeProject({ "package.json": { name: "ok", dependencies: { safe: "^1" } }, "package-lock.json": lock })));
      assert.match(full, />No known vulnerabilities found</);
      assert.ok(!/Coverage gaps/.test(full));
      assert.ok(!/<script>/.test(full), "no filter script when there is nothing to filter");

      const partial = renderHtml(await scan(await makeProject({ "package.json": { name: "ok", dependencies: { safe: "^1" } } })));
      assert.match(partial, /No known vulnerabilities found, but coverage is incomplete/);
      assert.match(partial, /No package-lock\.json, yarn\.lock or pnpm-lock\.yaml/);
    });
  } finally { osv.close(); }
});

test("html report: text from manifests and OSV is escaped (a hostile advisory can't inject script)", () => {
  const evil = `<img src=x onerror="alert(1)">`;
  const r: ScanResult = {
    project: { dir: "/x", name: `"><script>alert(1)</script>`, manifests: ["package.json"], deps: [], notes: [evil] },
    checked: { npm: 1 },
    findings: [{
      id: `GHSA-x"><b>`, aliases: [], summary: evil, severity: "high", fixed: [], url: "https://osv.dev/vulnerability/x",
      dep: { ecosystem: "npm", name: `<b>pkg</b>`, version: `1.0.0"onmouseover="x`, source: "lockfile", direct: true, dev: false, manifest: "package-lock.json" },
    }],
    counts: { critical: 0, high: 1, moderate: 0, low: 0, unknown: 0 },
    hidden: { ignored: 0, belowSeverity: 0, devSkipped: 0 },
    options: { minSeverity: "low", prodOnly: false, ignore: [`<i>`] },
    scannedAt: "2026-01-01T00:00:00.000Z",
  };
  const html = renderHtml(r);
  for (const bad of ["<img src=x", "<script>alert", "<b>pkg", "<i>", `"><b>`, `onmouseover="x`])
    assert.ok(!html.includes(bad), `raw ${bad} leaked into the page`);
  assert.ok(html.includes("&lt;img src=x onerror=&quot;alert(1)&quot;&gt;"));
  assert.equal((html.match(/<script/g) ?? []).length, 2, "only the Tailwind tag and our own filter script");
});

test("html report via CLI: --html writes the file (also when clean), keeps the exit code, and needs a path", async () => {
  const { spawn } = await import("node:child_process");
  const { fileURLToPath } = await import("node:url");
  const CLI = fileURLToPath(new URL("../src/cli.ts", import.meta.url));
  const run = (args: string[], env: Record<string, string>) =>
    new Promise<{ code: number | null; out: string; err: string }>((resolve) => {
      const c = spawn(process.execPath, ["--import", import.meta.resolve("tsx"), CLI, ...args], { env: { ...process.env, NO_COLOR: "1", ...env } });
      let out = "", err = "";
      c.stdout.on("data", (d) => (out += d));
      c.stderr.on("data", (d) => (err += d));
      c.on("close", (code) => resolve({ code, out, err }));
    });
  const osv = await fakeOsv();
  try {
    const env = { OSV_API_URL: osv.url };
    const dir = await makeProject(NPM_PROJECT);
    const file = join(dir, "out", "nested", "report.html");
    const bad = await run(["scan", dir, "--html", file], env);
    assert.equal(bad.code, 1, "vulnerabilities still fail the run");
    assert.match(bad.out, /release-radar scan: demo-app/, "text report still printed");
    assert.match(bad.err, /HTML report written to /);
    const html = await readFile(file, "utf8");
    assert.match(html, /GHSA-bbbb-qs/);

    const clean = await makeProject({ "package.json": { name: "ok", dependencies: { safe: "^1" } }, "package-lock.json": { lockfileVersion: 3, packages: { "": {}, "node_modules/safe": { version: "1.0.0" } } } });
    const okFile = join(clean, "report.html");
    assert.equal((await run(["scan", clean, "--html", okFile], env)).code, 0);
    assert.match(await readFile(okFile, "utf8"), />No known vulnerabilities found</);

    assert.equal((await run(["scan", clean, "--html"], env)).code, 2, "--html without a path is a usage error");
  } finally { osv.close(); }
});
