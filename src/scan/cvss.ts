export type Severity = "critical" | "high" | "moderate" | "low" | "unknown";
export const ORDER: Severity[] = ["low", "moderate", "high", "critical"];

const AV: Record<string, number> = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 };
const AC: Record<string, number> = { L: 0.77, H: 0.44 };
const UI: Record<string, number> = { N: 0.85, R: 0.62 };
const CIA: Record<string, number> = { H: 0.56, L: 0.22, N: 0 };
const PR_U: Record<string, number> = { N: 0.85, L: 0.62, H: 0.27 };
const PR_C: Record<string, number> = { N: 0.85, L: 0.68, H: 0.5 };

/** CVSS 3.1 "round up" to one decimal (spec Appendix A, avoids float artefacts). */
const roundUp = (x: number) => {
  const i = Math.round(x * 100000);
  return i % 10000 === 0 ? i / 100000 : (Math.floor(i / 10000) + 1) / 10;
};

/** Base score from a CVSS:3.x vector, or undefined for anything else (e.g. CVSS:4.0). */
export function cvss3Score(vector: string): number | undefined {
  if (!/^CVSS:3\.[01]\//.test(vector)) return undefined;
  const m: Record<string, string> = {};
  for (const part of vector.split("/").slice(1)) {
    const [k, v] = part.split(":");
    m[k] = v;
  }
  if (m.S !== "U" && m.S !== "C") return undefined;
  const changed = m.S === "C";
  const av = AV[m.AV], ac = AC[m.AC], pr = (changed ? PR_C : PR_U)[m.PR], ui = UI[m.UI];
  const c = CIA[m.C], i = CIA[m.I], a = CIA[m.A];
  if ([av, ac, pr, ui, c, i, a].some((x) => x === undefined)) return undefined;
  const iss = 1 - (1 - c) * (1 - i) * (1 - a);
  const impact = changed ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15) : 6.42 * iss;
  const exploit = 8.22 * av * ac * pr * ui;
  if (impact <= 0) return 0;
  return changed ? roundUp(Math.min(1.08 * (impact + exploit), 10)) : roundUp(Math.min(impact + exploit, 10));
}

export function severityFromScore(score: number): Severity {
  return score >= 9 ? "critical" : score >= 7 ? "high" : score >= 4 ? "moderate" : score > 0 ? "low" : "unknown";
}

/** Severity of an OSV vulnerability record: GitHub's label if present, else computed from a CVSS v3 vector. */
export function severityOf(v: any): { severity: Severity; score?: number } {
  const label = String(v?.database_specific?.severity ?? "").toLowerCase();
  const fromLabel: Severity | undefined =
    label === "critical" ? "critical" : label === "high" ? "high" : label === "moderate" || label === "medium" ? "moderate" : label === "low" ? "low" : undefined;
  let score: number | undefined;
  for (const s of Array.isArray(v?.severity) ? v.severity : []) {
    const sc = typeof s?.score === "string" ? cvss3Score(s.score) : undefined;
    if (sc !== undefined) score = Math.max(score ?? 0, sc);
  }
  if (fromLabel) return { severity: fromLabel, score };
  return score !== undefined ? { severity: severityFromScore(score), score } : { severity: "unknown" };
}

/** "unknown" is always kept: a threat we can't rate must not be silently dropped by a threshold. */
export const meets = (sev: Severity, min: Severity) => sev === "unknown" || ORDER.indexOf(sev) >= ORDER.indexOf(min);
