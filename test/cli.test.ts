import test from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { spawn } from "node:child_process";
import type { AddressInfo } from "node:net";
import { fileURLToPath } from "node:url";
import { COMPOSER_PROJECT, fakeOsv, makeProject, NPM_PROJECT } from "./helpers.js";

const CLI = fileURLToPath(new URL("../src/cli.ts", import.meta.url));

function run(args: string[], env: Record<string, string> = {}, cwd?: string) {
    return new Promise<{ code: number | null; out: string; err: string }>((resolve) => {
        const p = spawn(process.execPath, ["--import", import.meta.resolve("tsx"), CLI, ...args], { cwd, env: { ...process.env, NO_COLOR: "1", ...env } });
        let out = "", err = "";
        p.stdout.on("data", (d) => (out += d));
        p.stderr.on("data", (d) => (err += d));
        p.on("close", (code) => resolve({ code, out, err }));
    });
}

test("cli: `scan` on a vulnerable project exits 1, runs from cwd with no args, and prints the report", async () => {
    const osv = await fakeOsv();
    try {
        const dir = await makeProject({ ...NPM_PROJECT, ...COMPOSER_PROJECT });
        const r = await run([], { OSV_API_URL: osv.url }, dir); // no subcommand, no dir: scans the current directory
        assert.equal(r.code, 1);
        assert.match(r.out, /release-radar scan: demo-app/);
        assert.match(r.out, /CRITICAL\s+qs@6\.5\.0/);
        assert.match(r.out, /laravel\/framework@11\.9\.0/);
    } finally { osv.close(); }
});

test("cli: --json, --no-fail, --min-severity, --prod, --ignore", async () => {
    const osv = await fakeOsv();
    try {
        const dir = await makeProject({ ...NPM_PROJECT, ...COMPOSER_PROJECT });
        const env = { OSV_API_URL: osv.url };
        const j = await run(["scan", dir, "--json", "--no-fail", "--min-severity", "critical"], env);
        assert.equal(j.code, 0);
        assert.deepEqual(JSON.parse(j.out).vulnerabilities.map((v: any) => v.package), ["qs"]);
        const p = await run(["scan", dir, "--json", "--prod", "--ignore", "GHSA-bbbb-qs", "--ignore", "GHSA-aaaa-lodash"], env);
        assert.deepEqual(JSON.parse(p.out).vulnerabilities.map((v: any) => v.id).sort(), ["GHSA-cccc-laravel", "GHSA-dddd-lodash"]);
    } finally { osv.close(); }
});

test("cli: clean project exits 0; bad input / no manifests / unreachable OSV exit 2", async () => {
    const osv = await fakeOsv();
    try {
        const clean = await makeProject({ "package.json": { name: "ok", dependencies: { safe: "^1" } }, "package-lock.json": { lockfileVersion: 3, packages: { "node_modules/safe": { version: "1.0.0" } } } });
        assert.equal((await run(["scan", clean], { OSV_API_URL: osv.url })).code, 0);
        assert.equal((await run(["scan", clean, "--min-severity", "bogus"])).code, 2);
        assert.equal((await run(["scan", clean, "--nope"])).code, 2);
        const empty = await run(["scan", await makeProject({ "x.txt": "y" })], { OSV_API_URL: osv.url });
        assert.equal(empty.code, 2);
        assert.match(empty.err, /No package\.json or composer\.json/);
        const down = await run(["scan", clean], { OSV_API_URL: "http://127.0.0.1:9" });
        assert.equal(down.code, 2);
        assert.match(down.err, /Cannot reach OSV/);
    } finally { osv.close(); }
});

test("cli: --help and --version", async () => {
    assert.match((await run(["--help"])).out, /Check package\.json \/ composer\.json/);
    assert.match((await run(["--version"])).out, /^\d+\.\d+\.\d+/);
});

test("cli: --notify sends exactly ONE summary alert, and the project's own .env is never read", async () => {
    const osv = await fakeOsv();
    const posts: string[] = [];
    const slack = http.createServer((q, s) => { let b = ""; q.on("data", (c) => (b += c)); q.on("end", () => { posts.push(b); s.writeHead(200).end("ok"); }); }).listen(0, "127.0.0.1");
    await new Promise((r) => slack.once("listening", r));
    const slackUrl = `http://127.0.0.1:${(slack.address() as AddressInfo).port}/services/T/B/SECRET`;
    try {
        // the scanned project has its own .env that tries to hijack alerts: it must be ignored
        const dir = await makeProject({ ...NPM_PROJECT, ".env": "SLACK_WEBHOOK_URL=http://127.0.0.1:9/hijack\n" });
        const envFile = (await makeProject({ "radar.env": `SLACK_WEBHOOK_URL=${slackUrl}\n` })) + "/radar.env";

        const none = await run(["scan", dir, "--notify"], { OSV_API_URL: osv.url });
        assert.match(none.err, /no channels configured/);
        assert.equal(posts.length, 0);

        const r = await run(["scan", dir, "--notify", "--env-file", envFile], { OSV_API_URL: osv.url });
        assert.equal(r.code, 1);
        assert.equal(posts.length, 1, "one message for all findings, not one per finding");
        const text = JSON.parse(posts[0]).text as string;
        assert.match(text, /demo-app has 3 known vulnerabilities/);
        assert.match(text, /CRITICAL qs@6\.5\.0/);
        assert.ok(!r.err.includes("SECRET"), "no webhook secret in logs");
        assert.match(r.err, /alert sent via slack/);
    } finally { osv.close(); slack.close(); }
});
