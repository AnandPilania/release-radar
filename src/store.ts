import { readFile, writeFile, rename } from "node:fs/promises";
import { isDry } from "./flags.js";

interface State {
  seen: Record<string, string>; // dedupe key -> first seen ISO
  http: Record<string, { etag?: string; lastModified?: string }>;
  baselined: string[]; // sources whose first poll was silent
  mail?: { uidValidity: string; lastUid: number };
}

const file = () => process.env.STATE_FILE ?? "state.json";
const fresh = (): State => ({ seen: {}, http: {}, baselined: [] });

export async function loadState(): Promise<State> {
  if (isDry()) return fresh(); // dry runs never read or write disk, so they can't "use up" real alerts
  const f = file();
  let text: string;
  try {
    text = await readFile(f, "utf8");
  } catch (e: any) {
    if (e.code === "ENOENT") return fresh();
    throw e;
  }
  try {
    return { ...fresh(), ...JSON.parse(text) };
  } catch {
    // Never silently start over: that would re-baseline and swallow real alerts without a trace.
    const bak = `${f}.corrupt-${Date.now()}`;
    await rename(f, bak);
    console.error(`[state] ${f} is corrupt; moved to ${bak} and starting fresh (sources will re-baseline silently)`);
    return fresh();
  }
}

export async function saveState(s: State): Promise<void> {
  if (isDry()) return;
  const f = file();
  const tmp = f + ".tmp";
  await writeFile(tmp, JSON.stringify(s));
  await rename(tmp, f); // atomic swap, safe on crash
}

export type { State };
