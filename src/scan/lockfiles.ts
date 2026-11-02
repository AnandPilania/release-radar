import { parse as parseYaml } from "yaml";

/** A package exactly as a lockfile pins it. */
export interface LockedPkg {
  name: string;
  version: string;
  direct: boolean;
  dev: boolean;
}

export interface Parsed {
  pkgs: LockedPkg[];
  /** Entries we could not match to a registry version (git, file, workspace, patched...). Reported, never silently dropped. */
  skipped: string[];
}

/** package.json's declared dependencies: name -> range. */
export interface Declared {
  prod: Record<string, string>;
  dev: Record<string, string>;
}

/** Specs that don't point at a registry version (git, tarball URL, file, workspace, owner/repo shorthand...). */
export const isRegistrySpec = (range: string): boolean =>
  !/^(file|link|git|github|gitlab|bitbucket|http|https|workspace|portal|patch|exec)[:+]/i.test(range.trim()) && !/^[\w.-]+\/[\w.-]+(#.*)?$/.test(range.trim());

/** One resolved package. Several lockfile keys (specs) can point at the same entry. */
interface Entry {
  name: string;
  version: string;
  /** Alternative keys per dependency; the first one that exists in the lockfile wins. */
  deps: string[][];
}

/**
 * Walk the dependency graph from package.json's roots so that `dev` means "only reachable from devDependencies".
 * Entries that no root reaches (workspace siblings, hoisting oddities) are treated as prod: --prod must never hide them.
 */
function resolve(byKey: Map<string, Entry>, declared: Declared): LockedPkg[] {
  const lookup = (alts: string[]) => alts.map((k) => byKey.get(k)).find(Boolean);
  const reach = (roots: string[][]) => {
    const seen = new Set<Entry>();
    const stack = roots.map(lookup).filter((e): e is Entry => !!e);
    while (stack.length) {
      const e = stack.pop()!;
      if (seen.has(e)) continue;
      seen.add(e);
      for (const d of e.deps) {
        const n = lookup(d);
        if (n && !seen.has(n)) stack.push(n);
      }
    }
    return seen;
  };
  const rootsOf = (m: Record<string, string>) => Object.entries(m).map(([n, r]) => [`${n}@${r}`, `${n}@npm:${r}`]);
  const prodRoots = rootsOf(declared.prod), devRoots = rootsOf(declared.dev);
  const prod = reach(prodRoots), all = reach([...prodRoots, ...devRoots]);
  const direct = new Set([...prodRoots, ...devRoots].map(lookup).filter((e): e is Entry => !!e));
  return [...new Set(byKey.values())].map((e) => ({ name: e.name, version: e.version, direct: direct.has(e), dev: all.has(e) && !prod.has(e) }));
}

/** "name@range" -> [name, range] (scoped names keep their leading @). npm aliases ("a@npm:b@^1") resolve to the real package b. */
function splitSpec(spec: string): [string, string] {
  const at = spec.indexOf("@", 1);
  if (at < 0) return [spec, ""];
  let name = spec.slice(0, at), range = spec.slice(at + 1);
  if (range.startsWith("npm:") && range.length > 4) {
    const real = range.slice(4), i = real.indexOf("@", 1);
    if (i > 0) { name = real.slice(0, i); range = real.slice(i + 1); }
  }
  return [name, range];
}

const unquote = (s: string) => s.replace(/^"(.*)"$/, "$1");

// --- yarn -------------------------------------------------------------------

function parseYarnV1(text: string, declared: Declared): Parsed {
  const byKey = new Map<string, Entry>();
  const skipped: string[] = [];
  let cur: (Entry & { specs: string[]; resolved: string }) | undefined;
  let inDeps = false;

  const finish = () => {
    if (!cur) return;
    const [name] = splitSpec(cur.specs[0]);
    cur.name = name;
    const bad = cur.specs.some((s) => !isRegistrySpec(splitSpec(s)[1])) || /^(git|.*codeload\.github\.com|.*github\.com\/.*\.tar)/i.test(cur.resolved);
    if (bad || !/^\d/.test(cur.version)) skipped.push(`${cur.specs[0]}`);
    else for (const s of cur.specs) byKey.set(s, cur);
    cur = undefined;
  };

  for (const raw of text.split(/\r?\n/)) {
    if (!raw.trim() || raw.trimStart().startsWith("#")) continue;
    const indent = raw.length - raw.trimStart().length;
    const line = raw.trim();
    if (indent === 0) {
      finish();
      inDeps = false;
      if (line.endsWith(":")) cur = { name: "", version: "", deps: [], specs: line.slice(0, -1).split(",").map((s) => unquote(s.trim())), resolved: "" };
    } else if (cur && indent === 2) {
      inDeps = /^(dependencies|optionalDependencies):$/.test(line);
      const v = line.match(/^version\s+"?([^"\s]+)"?$/);
      if (v) cur.version = v[1];
      const r = line.match(/^resolved\s+"?([^"\s]+)"?$/);
      if (r) cur.resolved = r[1];
    } else if (cur && indent === 4 && inDeps) {
      const m = line.match(/^(?:"([^"]+)"|(\S+))\s+(?:"([^"]*)"|(\S+))$/);
      if (m) cur.deps.push([`${m[1] ?? m[2]}@${m[3] ?? m[4]}`]);
    }
  }
  finish();
  return { pkgs: resolve(byKey, declared), skipped };
}

function parseYarnBerry(text: string, declared: Declared): Parsed {
  const doc = (parseYaml(text) ?? {}) as Record<string, any>;
  const byKey = new Map<string, Entry>();
  const skipped: string[] = [];
  for (const [key, val] of Object.entries(doc)) {
    if (key === "__metadata" || !val || typeof val !== "object") continue;
    const specs = key.split(",").map((s) => s.trim());
    const res = String(val.resolution ?? "");
    const m = res.match(/^(@?[^@]+)@npm:(\d[^@]*)$/); // "name@npm:1.2.3"; workspace:, patch:, git, file: don't match
    if (!m) {
      if (!/@workspace:/.test(res)) skipped.push(specs[0]);
      continue;
    }
    const deps = Object.entries<string>({ ...(val.dependencies ?? {}) }).map(([n, r]) => [`${n}@npm:${r}`, `${n}@${r}`]);
    const e: Entry = { name: m[1], version: m[2], deps };
    for (const s of specs) byKey.set(s, e);
  }
  return { pkgs: resolve(byKey, declared), skipped };
}

export function parseYarn(text: string, declared: Declared): Parsed {
  return /^__metadata:/m.test(text) ? parseYarnBerry(text, declared) : parseYarnV1(text, declared);
}

// --- pnpm -------------------------------------------------------------------

/** Split a pnpm package key into name, version and the full key (peer suffix kept: it distinguishes variants). Handles lockfile v5 ("/n/1.0.0_peer"), v6 ("/n@1.0.0(peer)") and v9 ("n@1.0.0(peer)"). */
function pnpmKey(raw: string, major: number): { name: string; version: string; full: string } | undefined {
  const k = raw.replace(/^\//, "");
  if (major <= 5) {
    const i = k.lastIndexOf("/");
    if (i <= 0) return undefined;
    const name = k.slice(0, i), rest = k.slice(i + 1);
    return { name, version: rest.split("_")[0], full: `${name}@${rest}` };
  }
  const base = k.split("(")[0], i = base.lastIndexOf("@");
  if (i <= 0) return undefined;
  return { name: base.slice(0, i), version: base.slice(i + 1), full: k };
}

export function parsePnpm(text: string): Parsed {
  const doc = (parseYaml(text) ?? {}) as Record<string, any>;
  const major = parseInt(String(doc.lockfileVersion ?? "9"), 10) || 9;
  const importers: Record<string, any> = doc.importers ?? { ".": doc }; // v5/v6 single projects keep these at the top level
  const packages: Record<string, any> = doc.packages ?? {};
  const graph: Record<string, any> = major >= 9 ? (doc.snapshots ?? {}) : packages;
  const skipped: string[] = [];

  // an edge's target key: plain version, alias ("npm:real@1" / "real@1" / "/real/1"), or something we can't follow (link:, file:)
  const target = (name: string, v: unknown): string | undefined => {
    const s = String(v);
    if (/^(link|file|workspace|portal):/.test(s)) return undefined;
    if (s.startsWith("/")) return pnpmKey(s, major)?.full;
    if (/^\D/.test(s) && s.includes("@")) return s.replace(/^npm:/, "");
    return `${name}@${s}`;
  };

  const byKey = new Map<string, Entry>();
  for (const [raw, e] of Object.entries<any>(graph)) {
    const k = pnpmKey(raw, major);
    if (!k) continue;
    const meta = major >= 9 ? packages[k.full.split("(")[0]] ?? e : e;
    const res = meta?.resolution ?? {};
    if (!/^\d/.test(k.version) || res.type || res.repo || res.directory || /codeload\.github\.com|^git/i.test(String(res.tarball ?? ""))) {
      skipped.push(`${k.name}@${k.version}`);
      continue;
    }
    const deps = Object.entries({ ...(e?.dependencies ?? {}), ...(e?.optionalDependencies ?? {}) })
      .map(([n, v]) => target(n, v))
      .filter((x): x is string => !!x)
      .map((x) => [x]);
    byKey.set(k.full, { name: k.name, version: k.version, deps });
  }

  // roots: every importer (monorepos have many), prod vs dev by section
  const keyOf = (n: string, spec: any) => target(n, spec?.version ?? spec);
  const rootKeys = { prod: [] as string[], dev: [] as string[] };
  for (const imp of Object.values<any>(importers))
    for (const [section, into] of [["dependencies", rootKeys.prod], ["optionalDependencies", rootKeys.prod], ["devDependencies", rootKeys.dev]] as const)
      for (const [n, spec] of Object.entries<any>(imp?.[section] ?? {})) {
        const key = keyOf(n, spec);
        if (key) into.push(key);
      }

  const lookup = (k: string) => byKey.get(k);
  const reach = (roots: string[]) => {
    const seen = new Set<Entry>();
    const stack = roots.map(lookup).filter((e): e is Entry => !!e);
    while (stack.length) {
      const e = stack.pop()!;
      if (seen.has(e)) continue;
      seen.add(e);
      for (const [d] of e.deps) {
        const n = lookup(d);
        if (n && !seen.has(n)) stack.push(n);
      }
    }
    return seen;
  };
  const prodSet = reach(rootKeys.prod), allSet = reach([...rootKeys.prod, ...rootKeys.dev]);
  const directSet = new Set([...rootKeys.prod, ...rootKeys.dev].map(lookup).filter((e): e is Entry => !!e));
  const pkgs = [...new Set(byKey.values())].map((e) => ({ name: e.name, version: e.version, direct: directSet.has(e), dev: allSet.has(e) && !prodSet.has(e) }));
  return { pkgs, skipped };
}
