import type { Severity } from "./cvss.js";
import { summaryLine, type ScanResult } from "./scan.js";

const COLORS: Record<Severity, string> = { critical: "1;97;41", high: "1;31", moderate: "33", low: "36", unknown: "35" };
const paint = (on: boolean, code: string, s: string) => (on ? `\u001b[${code}m${s}\u001b[0m` : s);

export function renderText(r: ScanResult, color = false): string {
  const L: string[] = [];
  const p = r.project;
  L.push(`release-radar scan: ${p.name}`);
  L.push(`Read: ${p.manifests.join(", ")}`);
  L.push(`Checked ${r.checked.npm} npm + ${r.checked.Packagist} Packagist packages against OSV.dev`);
  for (const n of p.notes) L.push(paint(color, "33", `! ${n}`));
  L.push("");

  if (!r.findings.length) {
    L.push(paint(color, "32", "No known vulnerabilities found."));
    return L.join("\n");
  }
  for (const f of r.findings) {
    const tags = [f.dep.direct ? "direct" : "transitive", f.dep.dev ? "dev" : "prod", f.dep.source === "declared-range" ? "version from range" : ""].filter(Boolean).join(", ");
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
    notes: r.project.notes,
    summary: r.counts,
    vulnerabilities: r.findings.map((f) => ({
      id: f.id,
      aliases: f.aliases,
      severity: f.severity,
      score: f.score ?? null,
      ecosystem: f.dep.ecosystem,
      package: f.dep.name,
      version: f.dep.version,
      direct: f.dep.direct,
      dev: f.dep.dev,
      versionSource: f.dep.source,
      fixedIn: f.fixed,
      upgradeTo: f.upgradeTo ?? null,
      summary: f.summary,
      url: f.url,
    })),
  };
}
