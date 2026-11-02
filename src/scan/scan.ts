import type { Item } from "../types.js";
import { meets, ORDER, type Severity } from "./cvss.js";
import { readProject, type Dep, type Ecosystem, type Project } from "./manifests.js";
import { cmpVersion, depKey, lookup, type Vuln } from "./osv.js";

export interface Finding extends Vuln {
  dep: Dep;
  /** Lowest fixed version newer than the installed one, if the advisory names any. */
  upgradeTo?: string;
}

export interface ScanOptions {
  minSeverity?: Severity;
  prodOnly?: boolean;
  ignore?: string[];
}

export interface ScanResult {
  project: Project;
  /** Packages sent to OSV, per ecosystem (only ecosystems that were present). */
  checked: Partial<Record<Ecosystem, number>>;
  findings: Finding[];
  counts: Record<Severity, number>;
  /** What the filters hid, so a clean-looking report can't hide that it was filtered. */
  hidden: { ignored: number; belowSeverity: number; devSkipped: number };
  options: Required<ScanOptions>;
  scannedAt: string;
}

const rank = (s: Severity) => (s === "unknown" ? 2.5 : ORDER.indexOf(s)); // unknown sorts between moderate and high

export async function scan(dir: string, o: ScanOptions = {}): Promise<ScanResult> {
  const project = await readProject(dir);
  const deps = project.deps.filter((d) => !(o.prodOnly && d.dev));
  const hits = await lookup(deps);
  const ignore = new Set((o.ignore ?? []).map((s) => s.trim().toUpperCase()));

  const findings: Finding[] = [];
  const hidden = { ignored: 0, belowSeverity: 0, devSkipped: project.deps.length - deps.length };
  for (const d of deps)
    for (const v of hits.get(depKey(d)) ?? []) {
      if (ignore.has(v.id.toUpperCase()) || v.aliases.some((a) => ignore.has(a.toUpperCase()))) { hidden.ignored++; continue; }
      if (!meets(v.severity, o.minSeverity ?? "low")) { hidden.belowSeverity++; continue; }
      findings.push({ ...v, dep: d, upgradeTo: v.fixed.find((f) => cmpVersion(f, d.version) > 0) });
    }
  findings.sort((a, b) => rank(b.severity) - rank(a.severity) || a.dep.name.localeCompare(b.dep.name));

  const counts: Record<Severity, number> = { critical: 0, high: 0, moderate: 0, low: 0, unknown: 0 };
  for (const f of findings) counts[f.severity]++;
  const checked: ScanResult["checked"] = {};
  for (const d of deps) checked[d.ecosystem] = (checked[d.ecosystem] ?? 0) + 1;
  return {
    project,
    checked,
    findings,
    counts,
    hidden,
    options: { minSeverity: o.minSeverity ?? "low", prodOnly: !!o.prodOnly, ignore: o.ignore ?? [] },
    scannedAt: new Date().toISOString(),
  };
}

const label = (n: number, one: string, many = one + "s") => `${n} ${n === 1 ? one : many}`;

export function summaryLine(r: ScanResult): string {
  const parts = (["critical", "high", "moderate", "low", "unknown"] as Severity[]).filter((s) => r.counts[s]).map((s) => `${r.counts[s]} ${s}`);
  return `${label(r.findings.length, "known vulnerability", "known vulnerabilities")} (${parts.join(", ")})`;
}

/** One alert for the whole project, so 30 findings are one message, not 30. */
export function toAlert(r: ScanResult): Item {
  const top = r.findings.slice(0, 6).map((f) => {
    const fix = f.upgradeTo ? ` -> fix: ${f.upgradeTo}` : "";
    return `${f.severity.toUpperCase()} ${f.dep.name}@${f.dep.version}: ${f.summary.slice(0, 80)}${fix}`;
  });
  const more = r.findings.length > top.length ? `\n+${r.findings.length - top.length} more` : "";
  const now = new Date().toISOString();
  return {
    id: `scan:${r.project.name}:${now}`,
    source: `Dependency scan: ${r.project.name}`,
    title: `${r.project.name} has ${summaryLine(r)}`,
    url: r.findings[0]?.url ?? "",
    summary: top.join("\n") + more,
    detectedAt: now,
    security: true,
  };
}
