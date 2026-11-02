#!/usr/bin/env node
import { readFileSync } from "node:fs";
import { parseArgs } from "node:util";
import { ORDER, type Severity } from "./scan/cvss.js";
import { renderText, toJson } from "./scan/report.js";
import { scan, toAlert } from "./scan/scan.js";
import { buildNotifiers, render } from "./notifiers.js";

const HELP = `release-radar: release & security alerts

Usage
  release-radar [scan] [dir]     Check package.json / composer.json (+ lockfiles) in dir (default: .)
                                 for known vulnerabilities (OSV.dev). Exit 1 if any are found.
  release-radar daemon [flags]   Run the always-on alerting service (feeds, GitHub webhook, mail).

Scan options
  --min-severity <level>   low | moderate | high | critical   (default: low; unrated advisories are always shown)
  --prod                   Skip devDependencies / require-dev
  --ignore <id>            Ignore an advisory by GHSA/CVE id (repeatable)
  --notify                 Also send ONE summary alert to your configured channels (Slack, Telegram, ...)
  --env-file <path>        Load channel settings from this file (the project's own .env is never read)
  --json                   Machine-readable output
  --no-fail                Always exit 0 (default: exit 1 when vulnerabilities are found)
  -h, --help   -v, --version

Exit codes: 0 clean, 1 vulnerabilities found, 2 error.
Env: OSV_API_URL overrides https://api.osv.dev (mirror / testing).
`;

const sub = process.argv[2];
if (sub === "daemon" || sub === "watch") {
  process.argv.splice(2, 1); // the daemon reads its own flags (--once, --dry, --replay, --test-alert)
  await import("./index.js");
} else {
  await main();
}

async function main() {
  let a;
  try {
    a = parseArgs({
      args: process.argv.slice(sub === "scan" ? 3 : 2),
      allowPositionals: true,
      options: {
        "min-severity": { type: "string", default: "low" },
        prod: { type: "boolean" },
        ignore: { type: "string", multiple: true },
        notify: { type: "boolean" },
        "env-file": { type: "string" },
        json: { type: "boolean" },
        "no-fail": { type: "boolean" },
        help: { type: "boolean", short: "h" },
        version: { type: "boolean", short: "v" },
      },
    });
  } catch (e: any) {
    console.error(`${e.message}\n\n${HELP}`);
    process.exit(2);
  }
  const v = a.values;
  if (v.help) return void console.log(HELP);
  if (v.version) return void console.log(JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")).version);
  if (!ORDER.includes(v["min-severity"] as Severity)) {
    console.error(`--min-severity must be one of: ${ORDER.join(", ")}`);
    process.exit(2);
  }

  try {
    if (v["env-file"]) process.loadEnvFile(v["env-file"]);
    const r = await scan(a.positionals[0] ?? ".", { minSeverity: v["min-severity"] as Severity, prodOnly: v.prod, ignore: v.ignore });
    console.log(v.json ? JSON.stringify(toJson(r), null, 2) : renderText(r, !!process.stdout.isTTY && !process.env.NO_COLOR));

    if (v.notify && r.findings.length) {
      const channels = buildNotifiers();
      if (!channels.length) console.error("--notify: no channels configured (set SLACK_WEBHOOK_URL etc., or pass --env-file).");
      const alert = toAlert(r);
      for (const c of channels)
        await c.send(alert, render(alert)).then(
          () => console.error(`alert sent via ${c.name}`),
          (e) => console.error(`[${c.name}] failed: ${e.message}`),
        );
    }
    process.exit(r.findings.length && !v["no-fail"] ? 1 : 0);
  } catch (e: any) {
    console.error(`error: ${e.message}`);
    process.exit(2);
  }
}
