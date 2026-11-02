/** Pure env/CLI helpers (no side effects, safe to import anywhere). */
export const flag = (v: string | undefined): boolean =>
  !!v && !["", "0", "false", "no", "off"].includes(v.trim().toLowerCase());

export const isDry = (): boolean => flag(process.env.DRY_RUN);

export const hasArg = (name: string): boolean => process.argv.includes(name);

export const argValue = (name: string): string | undefined => {
  const i = process.argv.indexOf(name);
  return i >= 0 ? process.argv[i + 1] : undefined;
};
