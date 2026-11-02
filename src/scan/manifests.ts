import { existsSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { basename, join, resolve } from "node:path";
import { isRegistrySpec, parsePnpm, parseYarn, type Declared, type Parsed } from "./lockfiles.js";
import { parseCargoLock, parsePipfileLock, parsePoetryLock, parseRequirements, tomlName, type Pinned } from "./others.js";

/** Names are the ones OSV uses. */
export type Ecosystem = "npm" | "Packagist" | "PyPI" | "crates.io";
export const ECOSYSTEMS: Ecosystem[] = ["npm", "Packagist", "PyPI", "crates.io"];

export interface Dep {
  ecosystem: Ecosystem;
  name: string;
  version: string;
  /** Where the exact version came from. "declared-range" is only the lowest version the range allows. */
  source: "lockfile" | "installed" | "declared-range";
  /** undefined = the lockfile doesn't say; we never guess "transitive". */
  direct?: boolean;
  dev: boolean;
  manifest: string;
}

export interface Project {
  dir: string;
  name: string;
  manifests: string[]; // files that were actually read
  deps: Dep[];
  notes: string[];     // things the user should know about the coverage of this scan
}

async function readJson(file: string): Promise<any | undefined> {
  let text: string;
  try {
    text = await readFile(file, "utf8");
  } catch (e: any) {
    if (e.code === "ENOENT") return undefined;
    throw e;
  }
  try {
    return JSON.parse(text);
  } catch {
    throw new Error(`${basename(file)} is not valid JSON`);
  }
}
const exists = async (f: string) => (await readJson(f).catch(() => null)) !== undefined;

/** Lowest concrete version a constraint allows ("^4.5.0" -> "4.5.0"). Undefined for non-registry specs. */
export function rangeFloor(range: string): string | undefined {
  const r = range.trim();
  if (!r || /^(file|link|git|github|gitlab|bitbucket|http|https|workspace|npm|dev-)/i.test(r) || /^[\w.-]+\/[\w.-]+(#.*)?$/.test(r)) return undefined;
  const m = r.split("||")[0].match(/\d+(?:\.\d+){0,2}(?:-[0-9A-Za-z.-]+)?/);
  if (!m) return undefined;
  const [core, pre] = m[0].split(/-(.+)/);
  const parts = core.split(".");
  while (parts.length < 3) parts.push("0");
  return parts.join(".") + (pre ? `-${pre}` : "");
}

const merge = (map: Map<string, Dep>, d: Dep) => {
  const key = `${d.ecosystem}:${d.name}@${d.version}`;
  const prev = map.get(key);
  if (!prev) return void map.set(key, d);
  prev.direct = prev.direct === true || d.direct === true ? true : (prev.direct ?? d.direct);
  prev.dev = prev.dev && d.dev; // used in production anywhere => not dev-only
};

const textLocks = ["yarn.lock", "pnpm-lock.yaml"] as const;

async function npmDeps(dir: string, project: Project): Promise<void> {
  const pkgFile = join(dir, "package.json");
  const pkg = await readJson(pkgFile);
  if (!pkg) return;
  project.manifests.push("package.json");
  if (pkg.name) project.name = pkg.name;

  const declared = new Map<string, { range: string; dev: boolean }>();
  for (const [k, dev] of [["dependencies", false], ["optionalDependencies", false], ["devDependencies", true]] as const)
    for (const [n, r] of Object.entries<string>(pkg[k] ?? {})) if (!declared.has(n) || !dev) declared.set(n, { range: String(r), dev });

  const npmLock = (await exists(join(dir, "package-lock.json"))) ? "package-lock.json" : (await exists(join(dir, "npm-shrinkwrap.json"))) ? "npm-shrinkwrap.json" : undefined;
  const present = textLocks.filter((f) => existsSync(join(dir, f)));
  // package.json's "packageManager" field says which lockfile is the real one when several exist
  const pm = String(pkg.packageManager ?? "").split("@")[0];
  const wanted = pm === "yarn" ? "yarn.lock" : pm === "pnpm" ? "pnpm-lock.yaml" : undefined;
  const textLock: (typeof textLocks)[number] | undefined = wanted && present.includes(wanted) ? wanted : npmLock ? undefined : present[0];
  const chosen = textLock ?? npmLock;
  const ignored = present.filter((f) => f !== chosen);
  if (chosen && ignored.length) project.notes.push(`Found ${ignored.join(" and ")} next to ${chosen}; only ${chosen} was checked. Set "packageManager" in package.json to choose.`);

  const out = new Map<string, Dep>();
  const skipped: string[] = [];
  const lockedNames = new Set<string>(); // names as package.json spells them (aliases included)
  const lockName = textLock ?? npmLock;

  if (textLock) {
    const text = await readFile(join(dir, textLock), "utf8");
    const split: Declared = { prod: {}, dev: {} };
    for (const [n, { range, dev }] of declared) (dev ? split.dev : split.prod)[n] = range;
    let parsed: Parsed;
    try {
      parsed = textLock === "yarn.lock" ? parseYarn(text, split) : parsePnpm(text);
    } catch (e: any) {
      throw new Error(`${textLock} could not be parsed (${e.message}). Fix or regenerate it, or run with another lockfile.`);
    }
    project.manifests.push(textLock);
    for (const p of parsed.pkgs) {
      lockedNames.add(p.name);
      merge(out, { ecosystem: "npm", name: p.name, version: p.version, source: "lockfile", direct: p.direct, dev: p.dev, manifest: textLock });
    }
    skipped.push(...parsed.skipped);
    if (text.trim() && !parsed.pkgs.length) project.notes.push(`${textLock} contained no registry packages we could read, so nothing was checked from it.`);
  } else if (npmLock) {
    const lock = await readJson(join(dir, npmLock));
    project.manifests.push(npmLock);
    const add = (key: string, name: string, version: unknown, dev: boolean, direct: boolean, resolved?: unknown) => {
      lockedNames.add(key);
      if (typeof resolved === "string" && (/^(git|file:|github:)/i.test(resolved) || /codeload\.github\.com/.test(resolved))) return void skipped.push(`${name}@${version}`);
      if (typeof version !== "string") return;
      if (!/^\d/.test(version)) return void (/^(file|link):/.test(version) || skipped.push(`${name}@${version}`)); // git/tarball versions: reported, not guessed
      merge(out, { ecosystem: "npm", name, version, source: "lockfile", direct: direct && declared.has(key), dev: declared.has(key) && direct ? declared.get(key)!.dev : dev, manifest: npmLock });
    };
    if (lock.packages) {
      for (const [key, e] of Object.entries<any>(lock.packages)) {
        if (!key.includes("node_modules/") || e.link) continue; // root, workspaces, symlinks
        const at = key.lastIndexOf("node_modules/") + "node_modules/".length;
        const pathName = key.slice(at);
        // an npm alias ("foo": "npm:bar@1") is installed at node_modules/foo but IS the package named in e.name: query that one
        const name = typeof e.name === "string" && e.name ? e.name : pathName;
        const topLevel = key.startsWith("node_modules/") && key.indexOf("node_modules/", "node_modules/".length) === -1; // a nested copy of a declared name is not the direct dependency
        add(pathName, name, e.version, !!e.dev, topLevel, e.resolved);
      }
    } else {
      const walk = (deps: Record<string, any> = {}, top = true) => {
        for (const [n, e] of Object.entries<any>(deps)) {
          const alias = typeof e.version === "string" ? e.version.match(/^npm:(@?[^@]+)@(\d.*)$/) : null; // lockfileVersion 1 alias
          add(n, alias ? alias[1] : n, alias ? alias[2] : e.version, !!e.dev, top, e.resolved);
          walk(e.dependencies, false);
        }
      };
      walk(lock.dependencies); // lockfileVersion 1
    }
  }

  if (lockName) {
    const stale = [...declared.keys()].filter((n) => !lockedNames.has(n) && isRegistrySpec(declared.get(n)!.range) && !declared.get(n)!.range.startsWith("npm:"));
    if (stale.length) project.notes.push(`${stale.slice(0, 3).join(", ")}${stale.length > 3 ? ` and ${stale.length - 3} more` : ""} ${stale.length === 1 ? "is" : "are"} in package.json but not in ${lockName}; the lockfile looks out of date (run your package manager's install).`);
    if (skipped.length) project.notes.push(`${skipped.length} npm package${skipped.length === 1 ? "" : "s"} from git, file or tarball sources can't be matched to a registry version and were NOT checked: ${skipped.slice(0, 5).join(", ")}${skipped.length > 5 ? ", ..." : ""}.`);
  } else {
    project.notes.push("No package-lock.json, yarn.lock or pnpm-lock.yaml: only direct dependencies are checked and transitive ones are NOT. Run your package manager's install to create a lockfile.");
    for (const [name, { range, dev }] of declared) {
      const installed = (await readJson(join(dir, "node_modules", name, "package.json")).catch(() => undefined))?.version;
      const version = typeof installed === "string" ? installed : rangeFloor(range);
      if (!version) {
        project.notes.push(`Skipped ${name}@${range} (not a registry version).`);
        continue;
      }
      merge(out, { ecosystem: "npm", name, version, source: installed ? "installed" : "declared-range", direct: true, dev, manifest: "package.json" });
    }
    if ([...out.values()].some((d) => d.source === "declared-range"))
      project.notes.push("Some versions come from the lowest version their range allows, not what is installed; results for them may over-report.");
  }
  for (const d of out.values()) project.deps.push(d);
}

async function composerDeps(dir: string, project: Project): Promise<void> {
  const json = await readJson(join(dir, "composer.json"));
  if (!json) return;
  project.manifests.push("composer.json");
  if (project.name === basename(resolve(dir)) && json.name) project.name = json.name;

  const isPackage = (n: string) => n.includes("/"); // skips php, ext-*, lib-*, composer-plugin-api
  const declared = new Map<string, { range: string; dev: boolean }>();
  for (const [k, dev] of [["require", false], ["require-dev", true]] as const)
    for (const [n, r] of Object.entries<string>(json[k] ?? {})) if (isPackage(n) && (!declared.has(n) || !dev)) declared.set(n, { range: String(r), dev });

  const out = new Map<string, Dep>();
  const lock = await readJson(join(dir, "composer.lock"));
  if (lock) {
    project.manifests.push("composer.lock");
    const devBranch: string[] = [];
    for (const [list, dev] of [["packages", false], ["packages-dev", true]] as const)
      for (const p of lock[list] ?? []) {
        const version = String(p.version ?? "").replace(/^v/i, "");
        if (!isPackage(p.name)) continue;
        if (!/^\d/.test(version)) { devBranch.push(`${p.name}@${p.version}`); continue; } // dev-main etc. can't be matched to advisories
        merge(out, { ecosystem: "Packagist", name: String(p.name).toLowerCase(), version, source: "lockfile", direct: declared.has(p.name), dev, manifest: "composer.lock" });
      }
    if (devBranch.length) project.notes.push(`${devBranch.length} Composer package${devBranch.length === 1 ? "" : "s"} pinned to a branch or commit have no release version to match and were NOT checked: ${devBranch.slice(0, 5).join(", ")}${devBranch.length > 5 ? ", ..." : ""}.`);
  } else {
    project.notes.push("No composer.lock: only direct dependencies are checked and transitive ones are NOT. Run composer install to create one.");
    for (const [name, { range, dev }] of declared) {
      const version = rangeFloor(range);
      if (!version) {
        project.notes.push(`Skipped ${name}@${range} (not a registry version).`);
        continue;
      }
      merge(out, { ecosystem: "Packagist", name: name.toLowerCase(), version, source: "declared-range", direct: true, dev, manifest: "composer.json" });
    }
    if (out.size) project.notes.push("Composer versions come from the lowest version each constraint allows, not what is installed; results may over-report.");
  }
  for (const d of out.values()) project.deps.push(d);
}


const readText = (f: string) => readFile(f, "utf8").catch((e: any) => (e.code === "ENOENT" ? undefined : Promise.reject(e)));

/** Add pinned packages, merging with anything already found (the same package often appears in poetry.lock AND requirements.txt). */
const addPinned = (project: Project, list: Pinned[], ecosystem: Ecosystem, manifest: string) => {
  const out = new Map<string, Dep>(project.deps.filter((d) => d.ecosystem === ecosystem).map((d) => [`${d.ecosystem}:${d.name}@${d.version}`, d]));
  const before = new Set(out.values());
  for (const p of list) merge(out, { ecosystem, name: p.name, version: p.version, source: "lockfile", direct: p.direct, dev: p.dev, manifest });
  for (const d of out.values()) if (!before.has(d)) project.deps.push(d);
};

async function pythonDeps(dir: string, project: Project): Promise<void> {
  const pip = await readJson(join(dir, "Pipfile.lock"));
  if (pip) {
    const r = parsePipfileLock(pip);
    project.manifests.push("Pipfile.lock");
    addPinned(project, r.pkgs, "PyPI", "Pipfile.lock");
    if (r.skipped) project.notes.push(`${r.skipped} Pipfile.lock package${r.skipped === 1 ? "" : "s"} (git, path or unpinned) were NOT checked.`);
  }
  const poetry = await readText(join(dir, "poetry.lock"));
  if (poetry !== undefined) {
    const r = parsePoetryLock(poetry);
    project.manifests.push("poetry.lock");
    addPinned(project, r.pkgs, "PyPI", "poetry.lock");
    if (r.skipped) project.notes.push(`${r.skipped} poetry.lock package${r.skipped === 1 ? "" : "s"} from git, URL or local paths were NOT checked.`);
    if (r.pkgs.length && !r.knowsDev) project.notes.push("poetry.lock does not record dev vs prod groups; all Python packages are treated as production (--prod can't exclude dev ones).");
  }
  for (const f of ["requirements.txt", "requirements-dev.txt", "dev-requirements.txt"]) {
    const text = await readText(join(dir, f));
    if (text === undefined) continue;
    const r = parseRequirements(text, /dev/.test(f));
    project.manifests.push(f);
    addPinned(project, r.pkgs, "PyPI", f);
    if (r.unpinned) project.notes.push(`${f}: ${r.unpinned} line${r.unpinned === 1 ? " is" : "s are"} not an exact "==" pin (ranges, URLs, editable installs) and ${r.unpinned === 1 ? "was" : "were"} NOT checked. Pin with pip-compile or "pip freeze" for full coverage.`);
  }
}

async function rustDeps(dir: string, project: Project): Promise<void> {
  const lock = await readText(join(dir, "Cargo.lock"));
  if (lock === undefined) return;
  project.manifests.push("Cargo.lock");
  const r = parseCargoLock(lock);
  addPinned(project, r.pkgs, "crates.io", "Cargo.lock");
  if (r.skipped) project.notes.push(`${r.skipped} Cargo.lock package${r.skipped === 1 ? "" : "s"} from git sources were NOT checked.`);
  if (r.pkgs.length) project.notes.push("Cargo.lock does not record dev vs prod; all Rust packages are treated as production.");
  const toml = await readText(join(dir, "Cargo.toml"));
  const n = toml && tomlName(toml, ["[package]", "[workspace.package]"]);
  if (n && !project.manifests.includes("package.json")) project.name = n;
}

export const SUPPORTED_FILES = ["package.json", "composer.json", "yarn.lock", "pnpm-lock.yaml", "requirements.txt", "Pipfile.lock", "poetry.lock", "Cargo.lock"];

/** Read every supported manifest / lockfile in `dir` into one list of exact dependencies. */
export async function readProject(dir: string): Promise<Project> {
  const abs = resolve(dir);
  const project: Project = { dir: abs, name: basename(abs), manifests: [], deps: [], notes: [] };
  await npmDeps(abs, project);
  await composerDeps(abs, project);
  await pythonDeps(abs, project);
  await rustDeps(abs, project);
  if (!project.manifests.length) throw new Error(`No supported dependency files found in ${abs} (looked for ${SUPPORTED_FILES.join(", ")})`);
  return project;
}
