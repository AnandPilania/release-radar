import { existsSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { basename, join, resolve } from "node:path";

export type Ecosystem = "npm" | "Packagist";

export interface Dep {
  ecosystem: Ecosystem;
  name: string;
  version: string;
  /** Where the exact version came from. "declared-range" is only the lowest version the range allows. */
  source: "lockfile" | "installed" | "declared-range";
  direct: boolean;
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
  prev.direct ||= d.direct;
  prev.dev = prev.dev && d.dev; // used in production anywhere => not dev-only
};

async function npmDeps(dir: string, project: Project): Promise<void> {
  const pkgFile = join(dir, "package.json");
  const pkg = await readJson(pkgFile);
  if (!pkg) return;
  project.manifests.push("package.json");
  if (pkg.name) project.name = pkg.name;

  const declared = new Map<string, { range: string; dev: boolean }>();
  for (const [k, dev] of [["dependencies", false], ["optionalDependencies", false], ["devDependencies", true]] as const)
    for (const [n, r] of Object.entries<string>(pkg[k] ?? {})) if (!declared.has(n) || !dev) declared.set(n, { range: String(r), dev });

  const lockName = (await exists(join(dir, "package-lock.json"))) ? "package-lock.json" : (await exists(join(dir, "npm-shrinkwrap.json"))) ? "npm-shrinkwrap.json" : undefined;
  const out = new Map<string, Dep>();

  if (lockName) {
    const lock = await readJson(join(dir, lockName));
    project.manifests.push(lockName);
    const add = (name: string, version: unknown, dev: boolean) => {
      if (typeof version !== "string" || !/^\d/.test(version)) return;
      merge(out, { ecosystem: "npm", name, version, source: "lockfile", direct: declared.has(name), dev: declared.has(name) ? declared.get(name)!.dev : dev, manifest: lockName });
    };
    if (lock.packages) {
      for (const [key, e] of Object.entries<any>(lock.packages)) {
        if (!key.includes("node_modules/") || e.link) continue; // root, workspaces, symlinks
        add(key.slice(key.lastIndexOf("node_modules/") + "node_modules/".length), e.version, !!e.dev);
      }
    } else {
      const walk = (deps: Record<string, any> = {}) => {
        for (const [n, e] of Object.entries<any>(deps)) {
          add(n, e.version, !!e.dev);
          walk(e.dependencies);
        }
      };
      walk(lock.dependencies); // lockfileVersion 1
    }
    for (const n of declared.keys())
      if (![...out.values()].some((d) => d.name === n)) {
        project.notes.push(`${n} is in package.json but not in ${lockName}; the lockfile looks out of date (run npm install).`);
        break;
      }
  } else {
    const other = ["yarn.lock", "pnpm-lock.yaml"].find((f) => existsSync(join(dir, f)));
    project.notes.push(
      other
        ? `Found ${other}, which is not supported yet. Only direct dependencies are checked; transitive ones are NOT.`
        : "No package-lock.json: only direct dependencies are checked and transitive ones are NOT. Run npm install to create one.",
    );
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
    for (const [list, dev] of [["packages", false], ["packages-dev", true]] as const)
      for (const p of lock[list] ?? []) {
        const version = String(p.version ?? "").replace(/^v/i, "");
        if (!isPackage(p.name) || !/^\d/.test(version)) continue; // dev-main etc. can't be matched to advisories
        merge(out, { ecosystem: "Packagist", name: String(p.name).toLowerCase(), version, source: "lockfile", direct: declared.has(p.name), dev, manifest: "composer.lock" });
      }
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


/** Read package.json / composer.json (+ lockfiles) in `dir` into one list of exact dependencies. */
export async function readProject(dir: string): Promise<Project> {
  const abs = resolve(dir);
  const project: Project = { dir: abs, name: basename(abs), manifests: [], deps: [], notes: [] };
  await npmDeps(abs, project);
  await composerDeps(abs, project);
  if (!project.manifests.length) throw new Error(`No package.json or composer.json found in ${abs}`);
  return project;
}
