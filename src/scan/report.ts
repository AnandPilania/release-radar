import type { Severity } from "./cvss.js";
import { ECOSYSTEMS } from "./manifests.js";
import { summaryLine, type Finding, type ScanResult } from "./scan.js";

const COLORS: Record<Severity, string> = { critical: "1;97;41", high: "1;31", moderate: "33", low: "36", unknown: "35" };
/** "412 npm + 96 Packagist packages"; only ecosystems that were present. */
const checkedLabel = (r: ScanResult) => {
    const parts = ECOSYSTEMS.filter((e) => r.checked[e]).map((e) => `${r.checked[e]} ${e}`);
    return parts.length ? `${parts.join(" + ")} packages` : "0 packages";
};
/** What the options hid, or "" when nothing was hidden. */
const hiddenLabel = (r: ScanResult) => {
    const parts = [
        r.hidden.ignored && `${r.hidden.ignored} ignored by --ignore`,
        r.hidden.belowSeverity && `${r.hidden.belowSeverity} below --min-severity ${r.options.minSeverity}`,
        r.hidden.devSkipped && `${r.hidden.devSkipped} dev-only package${r.hidden.devSkipped === 1 ? "" : "s"} skipped by --prod`,
    ].filter(Boolean);
    return parts.length ? `Hidden by your options: ${parts.join(", ")}` : "";
};
const tagsOf = (f: Finding) =>
    [f.dep.direct === true ? "direct" : f.dep.direct === false ? "transitive" : "", f.dep.dev ? "dev" : "prod", f.dep.source === "declared-range" ? "version from range" : ""].filter(Boolean);

const paint = (on: boolean, code: string, s: string) => (on ? `\u001b[${code}m${s}\u001b[0m` : s);

export function renderText(r: ScanResult, color = false): string {
    const L: string[] = [];
    const p = r.project;
    L.push(`release-radar scan: ${p.name}`);
    L.push(`Read: ${p.manifests.join(", ")}`);
    L.push(`Checked ${checkedLabel(r)} against OSV.dev`);
    const h = hiddenLabel(r);
    if (h) L.push(h);
    for (const n of p.notes) L.push(paint(color, "33", `! ${n}`));
    L.push("");

    if (!r.findings.length) {
        L.push(paint(color, "32", "No known vulnerabilities found."));
        return L.join("\n");
    }
    for (const f of r.findings) {
        const tags = tagsOf(f).join(", ");
        const ids = [f.id, ...f.aliases.filter((a) => a.startsWith("CVE-"))].join(" / ");
        L.push(`${paint(color, COLORS[f.severity], ` ${f.severity.toUpperCase().padEnd(8)}`)} ${f.dep.name}@${f.dep.version}  (${tags})`);
        L.push(`          ${ids}${f.score !== undefined ? `  CVSS ${f.score}` : ""}`);
        L.push(`          ${f.summary}`);
        L.push(`          ${f.upgradeTo ? `Fix: upgrade to ${f.upgradeTo} or later` : f.fixed.length ? `Fixed in: ${f.fixed.join(", ")}` : "No fixed version published yet"}`);
        L.push(`          ${f.url}`);
        L.push("");
    }
    L.push(paint(color, "1", `${p.name}: ${summaryLine(r)}`));
    return L.join("\n");
}

export function toJson(r: ScanResult) {
    return {
        project: r.project.name,
        manifests: r.project.manifests,
        checked: r.checked,
        scannedAt: r.scannedAt,
        notes: r.project.notes,
        hidden: r.hidden,
        summary: r.counts,
        vulnerabilities: r.findings.map((f) => ({
            id: f.id,
            aliases: f.aliases,
            severity: f.severity,
            score: f.score ?? null,
            ecosystem: f.dep.ecosystem,
            package: f.dep.name,
            version: f.dep.version,
            direct: f.dep.direct ?? null,
            dev: f.dep.dev,
            versionSource: f.dep.source,
            fixedIn: f.fixed,
            upgradeTo: f.upgradeTo ?? null,
            summary: f.summary,
            url: f.url,
        })),
    };
}

// --- HTML -------------------------------------------------------------------

const esc = (v: unknown) => String(v).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!);

/** Pinned on purpose: an unpinned CDN script is code that changes under you. */
export const TAILWIND_CDN = "https://cdn.tailwindcss.com/3.4.17";

const SEV_ORDER: Severity[] = ["critical", "high", "moderate", "low", "unknown"];
const SEV_BADGE: Record<Severity, string> = {
    critical: "bg-red-600 text-white",
    high: "bg-orange-500 text-white",
    moderate: "bg-amber-400 text-slate-900",
    low: "bg-sky-500 text-white",
    unknown: "bg-violet-500 text-white",
};
const SEV_BORDER: Record<Severity, string> = { critical: "border-l-red-600", high: "border-l-orange-500", moderate: "border-l-amber-400", low: "border-l-sky-500", unknown: "border-l-violet-500" };

const chip = (t: string, cls = "bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-300") => `<span class="inline-block rounded-full px-2 py-0.5 text-xs font-medium ${cls}">${esc(t)}</span>`;

function findingHtml(f: Finding): string {
    const cves = f.aliases.filter((a) => a.startsWith("CVE-"));
    const ids = [f.id, ...cves];
    const fix = f.upgradeTo ? `Upgrade to <strong>${esc(f.upgradeTo)}</strong> or later` : f.fixed.length ? `Fixed in ${esc(f.fixed.join(", "))}` : "No fixed version published yet";
    const href = `https://osv.dev/vulnerability/${encodeURIComponent(f.id)}`;
    const search = [f.dep.name, f.dep.version, ...ids, f.summary].join(" ").toLowerCase();
    return `
    <article data-finding data-sev="${f.severity}" data-dev="${f.dep.dev ? 1 : 0}" data-text="${esc(search)}" class="rounded-lg border border-slate-200 border-l-4 ${SEV_BORDER[f.severity]} bg-white p-4 shadow-sm dark:border-slate-800 dark:bg-slate-900 print:break-inside-avoid">
      <div class="flex flex-wrap items-center gap-2">
        <span class="rounded px-2 py-0.5 text-xs font-bold uppercase tracking-wide ${SEV_BADGE[f.severity]}">${esc(f.severity)}</span>
        ${f.score !== undefined ? chip(`CVSS ${f.score}`) : ""}
        <h3 class="font-mono text-sm font-semibold sm:text-base">${esc(f.dep.name)}<span class="text-slate-500 dark:text-slate-400">@${esc(f.dep.version)}</span></h3>
        <span class="ml-auto text-xs text-slate-500 dark:text-slate-400">${esc(f.dep.ecosystem)}</span>
      </div>
      <p class="mt-2 text-sm">${esc(f.summary)}</p>
      <div class="mt-3 flex flex-wrap gap-1.5">${tagsOf(f).map((t) => chip(t)).join("")}</div>
      <div class="mt-3 flex flex-wrap items-center justify-between gap-2 text-sm">
        <span class="font-mono text-xs text-slate-600 dark:text-slate-400">${ids.map(esc).join(" / ")}</span>
        <span class="text-emerald-700 dark:text-emerald-400">${fix}</span>
        <a class="text-indigo-600 underline hover:text-indigo-500 dark:text-indigo-400" href="${esc(href)}" target="_blank" rel="noopener noreferrer">View advisory</a>
      </div>
    </article>`;
}

/** A self-contained HTML report (Tailwind via CDN). Every string that came from a manifest or from OSV is escaped. */
export function renderHtml(r: ScanResult): string {
    const p = r.project;
    const sources = { lockfile: 0, installed: 0, "declared-range": 0 };
    let direct = 0, transitive = 0, unknownDirect = 0;
    for (const d of p.deps) {
        if (!r.options.prodOnly || !d.dev) {
            sources[d.source]++;
            if (d.direct === true) direct++;
            else if (d.direct === false) transitive++;
            else unknownDirect++;
        }
    }
    const total = Object.values(r.checked).reduce((a, b) => a + b, 0);
    const partial = p.notes.length > 0;
    const verdict = r.findings.length
        ? { cls: "border-red-300 bg-red-50 text-red-900 dark:border-red-900 dark:bg-red-950 dark:text-red-100", title: `${summaryLine(r)}`, sub: "Review the findings below and upgrade where a fix exists." }
        : partial
            ? { cls: "border-amber-300 bg-amber-50 text-amber-900 dark:border-amber-800 dark:bg-amber-950 dark:text-amber-100", title: "No known vulnerabilities found, but coverage is incomplete", sub: "Read the coverage notes below before treating this as a clean bill of health." }
            : { cls: "border-emerald-300 bg-emerald-50 text-emerald-900 dark:border-emerald-800 dark:bg-emerald-950 dark:text-emerald-100", title: "No known vulnerabilities found", sub: `${total} package${total === 1 ? "" : "s"} checked against OSV.dev.` };

    const cards = SEV_ORDER.map((s) => {
        const n = r.counts[s];
        const base = `rounded-lg border p-3 text-left ${n ? "border-slate-300 dark:border-slate-700" : "border-slate-200 opacity-60 dark:border-slate-800"} bg-white dark:bg-slate-900`;
        const inner = `<div class="text-2xl font-bold">${n}</div><div class="mt-0.5 text-xs font-semibold uppercase tracking-wide"><span class="mr-1 inline-block h-2 w-2 rounded-full ${SEV_BADGE[s].split(" ")[0]}"></span>${s}</div>`;
        return r.findings.length ? `<button type="button" data-sev-filter="${s}" class="${base} transition hover:shadow focus:outline-none focus:ring-2 focus:ring-indigo-500" title="Click to show or hide ${s}">${inner}</button>` : `<div class="${base}">${inner}</div>`;
    }).join("");

    const hidden = hiddenLabel(r);
    const optionRows = [
        ["Minimum severity", r.options.minSeverity],
        ["Production only", r.options.prodOnly ? "yes (dev dependencies skipped)" : "no"],
        ["Ignored advisories", r.options.ignore.length ? r.options.ignore.join(", ") : "none"],
    ];

    return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="generator" content="release-radar">
  <title>Dependency scan: ${esc(p.name)}</title>
  <script src="${TAILWIND_CDN}"></script>
</head>
<body class="bg-slate-50 text-slate-900 antialiased dark:bg-slate-950 dark:text-slate-100">
  <main class="mx-auto max-w-5xl px-4 py-8 sm:px-6">
    <header class="flex flex-wrap items-start justify-between gap-4">
      <div>
        <p class="text-xs font-semibold uppercase tracking-widest text-indigo-600 dark:text-indigo-400"><a href="https://github.com/anandpilania/release-radar">release-radar</a> &middot; dependency scan</p>
        <h1 class="mt-1 text-3xl font-bold tracking-tight">${esc(p.name)}</h1>
        <p class="mt-1 text-sm text-slate-500 dark:text-slate-400">Scanned ${esc(r.scannedAt.replace("T", " ").slice(0, 16))} UTC &middot; ${esc(checkedLabel(r))} &middot; data from <a class="underline" href="https://osv.dev" target="_blank" rel="noopener noreferrer">OSV.dev</a></p>
      </div>
      <button type="button" onclick="window.print()" class="rounded-md border border-slate-300 px-3 py-1.5 text-sm font-medium hover:bg-slate-100 print:hidden dark:border-slate-700 dark:hover:bg-slate-800">Print / save as PDF</button>
    </header>

    <section class="mt-6 rounded-lg border p-4 ${verdict.cls}">
      <h2 class="text-lg font-semibold">${esc(verdict.title)}</h2>
      <p class="mt-1 text-sm opacity-90">${esc(verdict.sub)}</p>
    </section>

    <section class="mt-4 grid grid-cols-2 gap-3 sm:grid-cols-5">${cards}</section>

    ${r.findings.length
            ? `<section class="mt-8">
      <div class="flex flex-wrap items-center gap-3 print:hidden">
        <h2 class="text-xl font-semibold">Findings <span class="text-sm font-normal text-slate-500 dark:text-slate-400">(showing <span id="shown">${r.findings.length}</span> of ${r.findings.length})</span></h2>
        <input id="q" type="search" placeholder="Filter by package, CVE, text..." class="ml-auto w-full rounded-md border border-slate-300 bg-white px-3 py-1.5 text-sm sm:w-64 dark:border-slate-700 dark:bg-slate-900">
        <label class="flex items-center gap-2 text-sm"><input id="prod" type="checkbox" class="h-4 w-4 rounded"> Production only</label>
      </div>
      <div class="mt-3 space-y-3">${r.findings.map(findingHtml).join("")}</div>
    </section>`
            : ""
        }

    <section class="mt-10">
      <h2 class="text-xl font-semibold">How far to trust this report</h2>
      <div class="mt-3 grid gap-4 md:grid-cols-2">
        <div class="rounded-lg border border-slate-200 bg-white p-4 dark:border-slate-800 dark:bg-slate-900">
          <h3 class="text-sm font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400">What was read</h3>
          <div class="mt-2 flex flex-wrap gap-1.5">${p.manifests.map((m) => chip(m, "bg-indigo-100 text-indigo-800 dark:bg-indigo-950 dark:text-indigo-200")).join("")}</div>
          <dl class="mt-3 space-y-1 text-sm">
            <div class="flex justify-between"><dt>Exact version from a lockfile</dt><dd class="font-mono">${sources.lockfile}</dd></div>
            <div class="flex justify-between"><dt>Version from installed node_modules</dt><dd class="font-mono">${sources.installed}</dd></div>
            <div class="flex justify-between"><dt>Lowest version a range allows (may over-report)</dt><dd class="font-mono ${sources["declared-range"] ? "text-amber-600 dark:text-amber-400" : ""}">${sources["declared-range"]}</dd></div>
            <div class="flex justify-between"><dt>Direct / transitive / not recorded</dt><dd class="font-mono">${direct} / ${transitive} / ${unknownDirect}</dd></div>
          </dl>
        </div>
        <div class="rounded-lg border border-slate-200 bg-white p-4 dark:border-slate-800 dark:bg-slate-900">
          <h3 class="text-sm font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400">Options used</h3>
          <dl class="mt-2 space-y-1 text-sm">${optionRows.map(([k, v]) => `<div class="flex justify-between gap-4"><dt>${esc(k)}</dt><dd class="text-right font-mono">${esc(v)}</dd></div>`).join("")}</dl>
          ${hidden ? `<p class="mt-3 rounded bg-amber-50 p-2 text-sm text-amber-900 dark:bg-amber-950 dark:text-amber-100">${esc(hidden)}</p>` : ""}
        </div>
      </div>
      ${partial
            ? `<div class="mt-4 rounded-lg border border-amber-300 bg-amber-50 p-4 dark:border-amber-800 dark:bg-amber-950">
        <h3 class="text-sm font-semibold text-amber-900 dark:text-amber-100">Coverage gaps in this scan</h3>
        <ul class="mt-2 list-disc space-y-1 pl-5 text-sm text-amber-900 dark:text-amber-100">${p.notes.map((n) => `<li>${esc(n)}</li>`).join("")}</ul>
      </div>`
            : ""
        }
      <ul class="mt-4 list-disc space-y-1 pl-5 text-sm text-slate-600 dark:text-slate-400">
        <li>Reports <em>known</em> advisories for the exact versions pinned in your lockfiles. A package with no advisory is not proven safe; new advisories appear daily, so re-scan regularly.</li>
        <li>Does not tell you whether your code calls the vulnerable function (no reachability analysis), and does not check runtime versions (Node.js, PHP, Python...).</li>
        <li>Only package names and versions were sent to OSV.dev, never your code.</li>
      </ul>
    </section>

    <footer class="mt-10 border-t border-slate-200 pt-4 text-xs text-slate-500 dark:border-slate-800 dark:text-slate-400">Generated by <a href="https://github.com/anandpilania/release-radar">release-radar</a>. Styling loads Tailwind from a CDN; offline, the report is still readable but unstyled.</footer>
  </main>
${r.findings.length
            ? `<script>
(function () {
  var cards = [].slice.call(document.querySelectorAll("[data-finding]"));
  var btns = [].slice.call(document.querySelectorAll("[data-sev-filter]"));
  var q = document.getElementById("q"), prod = document.getElementById("prod"), shown = document.getElementById("shown");
  var active = {};
  btns.forEach(function (b) { active[b.getAttribute("data-sev-filter")] = true; });
  function apply() {
    var n = 0, term = q.value.toLowerCase();
    cards.forEach(function (c) {
      var ok = active[c.getAttribute("data-sev")] && (!prod.checked || c.getAttribute("data-dev") === "0") && (!term || c.getAttribute("data-text").indexOf(term) !== -1);
      c.classList.toggle("hidden", !ok);
      if (ok) n++;
    });
    shown.textContent = n;
  }
  btns.forEach(function (b) {
    b.addEventListener("click", function () {
      var s = b.getAttribute("data-sev-filter");
      active[s] = !active[s];
      b.classList.toggle("opacity-40", !active[s]);
      apply();
    });
  });
  q.addEventListener("input", apply);
  prod.addEventListener("change", apply);
})();
</script>`
            : ""
        }
</body>
</html>
`;
}
