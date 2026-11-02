import type { Item, Notifier } from "./types.js";
import type { State } from "./store.js";
import { saveState } from "./store.js";
import { render } from "./notifiers.js";
import { canonGithub } from "./util.js";

/** Thrown when an alert reached ZERO channels. The item has been un-claimed so it can be retried. */
export class DeliveryError extends Error {
  constructor(public failed: Item[]) {
    super(`${failed.length} alert(s) could not be delivered to any channel`);
  }
}

export interface AlertResult {
  sent: Item[];   // delivered to at least one channel
  failed: Item[]; // attempted, delivered to none
}

/** Single choke point for every ingest path (poll, webhook, mail): dedupe, alert, persist. */
export class Pipeline {
  private saving: Promise<void> = Promise.resolve();
  constructor(public state: State, private notifiers: Notifier[]) {}

  persist() {
    return (this.saving = this.saving.then(() => saveState(this.state)));
  }
  flush() {
    return this.saving;
  }

  keyOf(i: Item): string {
    return i.key ?? canonGithub(i.url) ?? i.id;
  }

  /** Returns items not seen before and marks them seen (also dedupes within the batch). */
  claim(items: Item[]): Item[] {
    const fresh: Item[] = [];
    for (const i of items) {
      const k = this.keyOf(i);
      if (this.state.seen[k]) continue;
      this.state.seen[k] = i.detectedAt;
      fresh.push(i);
    }
    return fresh;
  }

  async alert(items: Item[], notify: "all" | "security"): Promise<AlertResult> {
    const out: AlertResult = { sent: [], failed: [] };
    const ordered = [...items].sort((a, b) => (a.publishedAt ?? "").localeCompare(b.publishedAt ?? ""));
    for (const i of ordered) {
      if (notify === "security" && !i.security) continue;
      const msg = render(i);
      // one broken channel must never block the others
      const ok = await Promise.all(
        this.notifiers.map(async (n) => {
          try {
            await n.send(i, msg);
            return true;
          } catch (e: any) {
            console.error(`[${n.name}] failed: ${e.message}`);
            return false;
          }
        }),
      );
      (ok.some(Boolean) ? out.sent : out.failed).push(i);
    }
    return out;
  }

  /** alert() + give failed items back (un-claim) so a later attempt can deliver them. Caller persists. */
  async deliver(items: Item[], notify: "all" | "security"): Promise<AlertResult> {
    const r = await this.alert(items, notify);
    for (const f of r.failed) delete this.state.seen[this.keyOf(f)];
    return r;
  }

  /** Push-style ingest (webhook, mail): claim, alert, persist. Throws DeliveryError if nothing got through. */
  async ingest(items: Item[], notify: "all" | "security"): Promise<number> {
    const fresh = this.claim(items);
    if (!fresh.length) return 0;
    const r = await this.deliver(fresh, notify);
    await this.persist();
    if (r.failed.length) throw new DeliveryError(r.failed);
    return fresh.length;
  }
}
