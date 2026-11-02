/** Readers for ecosystems whose lockfiles are simple enough to parse without a TOML library. Each returns exact, pinned versions only. */

export interface Pinned {
  name: string;
  version: string;
  dev: boolean;
  /** undefined = the file doesn't say (we never guess "transitive"). */
  direct?: boolean;
}

/** PEP 503 normalisation, the form OSV indexes PyPI packages under. */
export const pypiName = (n: string) => n.toLowerCase().replace(/[-_.]+/g, "-");

/** requirements.txt: only exact pins (`name==1.2.3`) can be matched to advisories. Everything else is counted so the report can say so. */
export function parseRequirements(text: string, dev: boolean): { pkgs: Pinned[]; unpinned: number } {
  const pkgs: Pinned[] = [];
  let unpinned = 0;
  const lines = text.replace(/\\\r?\n/g, " ").split(/\r?\n/); // join "\" continuations (hash lists)
  for (let line of lines) {
    line = line.replace(/(^|\s)#.*$/, "").trim();
    if (!line || line.startsWith("-")) continue; // -r / -c / -e / --hash / --index-url ...
    const m = line.match(/^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*==\s*(\d[A-Za-z0-9._+!-]*)(?=\s|;|$)/);
    if (m && !m[2].includes("*")) pkgs.push({ name: pypiName(m[1]), version: m[2], dev }); // a requirements file can be hand-written or a full freeze: direct vs transitive is unknowable
    else unpinned++;
  }
  return { pkgs, unpinned };
}

/** Pipfile.lock: { default: { name: { version: "==1.2.3" } }, develop: { ... } } */
export function parsePipfileLock(lock: any): { pkgs: Pinned[]; skipped: number } {
  const pkgs: Pinned[] = [];
  let skipped = 0;
  for (const [section, dev] of [["default", false], ["develop", true]] as const)
    for (const [name, e] of Object.entries<any>(lock?.[section] ?? {})) {
      const v = typeof e?.version === "string" ? e.version.match(/^==\s*(\d\S*)$/)?.[1] : undefined;
      if (v) pkgs.push({ name: pypiName(name), version: v, dev });
      else skipped++; // git / path / editable
    }
  return { pkgs, skipped };
}

interface TomlPackage { name?: string; version?: string; source?: string; category?: string; sourceType?: string }

/** The `[[package]]` tables of a poetry.lock / Cargo.lock. Only top-level scalar keys of each table are read. */
function tomlPackages(text: string): TomlPackage[] {
  const out: TomlPackage[] = [];
  let cur: TomlPackage | undefined;
  let nested = false; // inside [package.source] etc.
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (line === "[[package]]") { cur = {}; out.push(cur); nested = false; continue; }
    if (line.startsWith("[")) {
      nested = /^\[package\./.test(line);
      if (nested && cur && /^\[package\.source\]/.test(line)) cur.sourceType = "pending";
      if (!nested) cur = undefined;
      continue;
    }
    if (!cur) continue;
    const m = line.match(/^(name|version|source|category|type)\s*=\s*"([^"]*)"/);
    if (!m) continue;
    if (nested) { if (m[1] === "type" && cur.sourceType === "pending") cur.sourceType = m[2]; continue; }
    if (m[1] === "name") cur.name = m[2];
    else if (m[1] === "version") cur.version = m[2];
    else if (m[1] === "source") cur.source = m[2];
    else if (m[1] === "category") cur.category = m[2];
  }
  return out;
}

export function parsePoetryLock(text: string): { pkgs: Pinned[]; skipped: number; knowsDev: boolean } {
  const pkgs: Pinned[] = [];
  let skipped = 0, knowsDev = false;
  for (const p of tomlPackages(text)) {
    if (!p.name || !p.version) continue;
    if (p.sourceType && p.sourceType !== "legacy" && p.sourceType !== "pending") { skipped++; continue; } // git / url / directory / file
    if (p.category) knowsDev = true;
    pkgs.push({ name: pypiName(p.name), version: p.version, dev: p.category === "dev" });
  }
  return { pkgs, skipped, knowsDev };
}

/** Cargo.lock: only packages from a registry have a `source = "registry+..."`; path/workspace members have none and git ones say `git+`. */
export function parseCargoLock(text: string): { pkgs: Pinned[]; skipped: number } {
  const pkgs: Pinned[] = [];
  let skipped = 0;
  for (const p of tomlPackages(text)) {
    if (!p.name || !p.version) continue;
    if (p.source?.startsWith("registry+") || p.source?.startsWith("sparse+")) pkgs.push({ name: p.name, version: p.version, dev: false });
    else if (p.source) skipped++; // git
  }
  return { pkgs, skipped };
}

/** `name = "x"` inside the first matching TOML table, for a friendlier project name. */
export function tomlName(text: string, tables: string[]): string | undefined {
  let inTable = false;
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (line.startsWith("[")) { inTable = tables.includes(line); continue; }
    const m = inTable && line.match(/^name\s*=\s*"([^"]+)"/);
    if (m) return m[1];
  }
  return undefined;
}
