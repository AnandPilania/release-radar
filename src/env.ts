/** Side-effect module: import it first. Loads .env (if present) and maps --dry to DRY_RUN. */
import { existsSync } from "node:fs";
import { hasArg } from "./flags.js";

const file = process.env.ENV_FILE ?? ".env";
if (existsSync(file)) {
  try {
    process.loadEnvFile(file); // never overrides variables already set in the real environment
  } catch (e: any) {
    console.error(`[env] could not load ${file}: ${e.message}`);
  }
}
if (hasArg("--dry")) process.env.DRY_RUN = "1";
