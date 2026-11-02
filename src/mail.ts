import { ImapFlow } from "imapflow";
import { simpleParser, type ParsedMail } from "mailparser";
import type { Item, MailRule } from "./types.js";
import type { State } from "./store.js";
import { DeliveryError } from "./pipeline.js";
import { canonGithub, isSecurity, sleep, strip } from "./util.js";

const URL_RE = /https?:\/\/[^\s<>"')\]]+/g;
const RELEASE_URL = /https?:\/\/github\.com\/[^/\s]+\/[^/\s]+\/releases\/tag\/[^\s<>"')\]]+/i;

const has = (hay: string | undefined, needle?: string) =>
  !needle || (hay ?? "").toLowerCase().includes(needle.toLowerCase());

/**
 * Is this message really from the domain in its From header, according to the RECEIVING server?
 * Uses the top-most Authentication-Results (added by our own mail host; RFC 8601). Accepts dmarc=pass,
 * or dkim=pass whose signing domain matches the From domain. Mailing-list mail usually re-signs under the
 * list's domain, so only turn requireAuth on for direct senders (e.g. notifications@github.com).
 */
export function authenticated(m: ParsedMail): boolean {
  const line = m.headerLines.find((h) => h.key === "authentication-results")?.line ?? "";
  if (!line) return false;
  const ar = line.replace(/\s+/g, " ").toLowerCase();
  if (/dmarc=pass/.test(ar)) return true;
  const fromDomain = m.from?.value?.[0]?.address?.split("@")[1]?.toLowerCase();
  if (!fromDomain) return false;
  const signers = [...ar.matchAll(/dkim=pass[^;]*?header\.(?:d|i)=@?([a-z0-9.-]+)/g)].map((x) => x[1]);
  return signers.some((d) => d === fromDomain || d.endsWith(`.${fromDomain}`) || fromDomain.endsWith(`.${d}`));
}

/** Raw, unfolded text of the first header with this name. (mailparser's headers map does NOT expose List-Id.) */
const headerText = (m: ParsedMail, key: string): string => {
  const line = m.headerLines.find((h) => h.key === key)?.line ?? "";
  return line.slice(line.indexOf(":") + 1).replace(/\s+/g, " ").trim();
};

export function mailToItem(
  m: ParsedMail,
  rules: MailRule[],
  keywords: string[],
): { item: Item; notify: "all" | "security" } | null {
  const from = m.from?.text;
  const listId = headerText(m, "list-id");
  const subject = m.subject ?? "";
  const rule = rules.find((r) => has(from, r.from) && has(listId, r.listId) && has(subject, r.subjectContains));
  if (!rule) return null;
  if (rule.requireAuth && !authenticated(m)) {
    console.error(`[mail] dropped "${subject.slice(0, 80)}": matched "${rule.name}" but sender not authenticated`);
    return null;
  }

  const body = m.text ?? strip(String(m.html || ""));
  const releaseUrl = body.match(RELEASE_URL)?.[0];
  const url = releaseUrl ?? body.match(URL_RE)?.[0] ?? "";
  const messageId = m.messageId ?? `${subject}:${m.date?.toISOString()}`;
  return {
    notify: rule.notify ?? "all",
    item: {
      id: `mail:${messageId}`,
      // a GitHub release mail and the releases.atom entry collapse to the same key
      key: canonGithub(releaseUrl) ?? `mail:${messageId}`,
      source: rule.name,
      title: subject.replace(/\s+/g, " ").trim(),
      url,
      summary: strip(body).slice(0, 400),
      publishedAt: m.date?.toISOString(),
      detectedAt: new Date().toISOString(),
      security: isSecurity(`${subject} ${body}`, keywords),
    },
  };
}

/** IMAP IDLE listener: the server pushes "new mail" to us, so latency is ~seconds. */
export async function startMail(o: {
  rules: MailRule[];
  keywords: string[];
  state: State;
  persist: () => Promise<void>;
  onItem: (item: Item, notify: "all" | "security") => Promise<void>;
  signal?: AbortSignal;
}) {
  const env = process.env;
  const port = Number(env.IMAP_PORT ?? 993);
  let backoff = 5;

  while (!o.signal?.aborted) {
    const client = new ImapFlow({
      host: env.IMAP_HOST!,
      port,
      secure: port === 993,
      auth: { user: env.IMAP_USER!, pass: env.IMAP_PASS! },
      logger: false,
    });
    client.on("error", (e) => console.error("[mail] imap error:", e.message));
    const onAbort = () => client.close();
    o.signal?.addEventListener("abort", onAbort, { once: true });
    try {
      await client.connect();
      const lock = await client.getMailboxLock(env.IMAP_MAILBOX ?? "INBOX");
      try {
        const box = client.mailbox as any;
        const validity = String(box.uidValidity);
        if (!o.state.mail || o.state.mail.uidValidity !== validity) {
          // first run (or mailbox rebuilt): baseline, don't alert on old mail
          o.state.mail = { uidValidity: validity, lastUid: box.uidNext - 1 };
          await o.persist();
        }
        console.log(`[mail] connected, watching ${env.IMAP_MAILBOX ?? "INBOX"} (${o.rules.length} rules)`);
        backoff = 5;

        let draining = false;
        let again = false;
        const drain = async (): Promise<void> => {
          if (draining) return void (again = true);
          draining = true;
          let undelivered = false;
          try {
            do {
              again = false;
              const last = o.state.mail!.lastUid;
              for await (const msg of client.fetch(`${last + 1}:*`, { uid: true, source: true }, { uid: true })) {
                if (msg.uid <= o.state.mail!.lastUid) continue; // IMAP "n:*" always returns the last message
                if (undelivered) continue; // keep order: don't advance past a message we failed to deliver
                try {
                  const hit = mailToItem(await simpleParser(msg.source as Buffer), o.rules, o.keywords);
                  if (hit) await o.onItem(hit.item, hit.notify);
                } catch (e: any) {
                  if (e instanceof DeliveryError) {
                    undelivered = true; // leave lastUid where it is; retried below
                    continue;
                  }
                  console.error("[mail] message", msg.uid, e.message); // unparsable: skip, don't wedge the mailbox
                }
                o.state.mail!.lastUid = msg.uid;
              }
              await o.persist();
            } while (again);
          } finally {
            draining = false;
          }
          if (undelivered) {
            console.error("[mail] alert reached no channel; retrying in 60s");
            setTimeout(() => drain().catch((e) => console.error("[mail] drain:", e.message)), 60_000).unref();
          }
        };

        client.on("exists", () => drain().catch((e) => console.error("[mail] drain:", e.message)));
        await drain(); // catch up on anything that arrived while we were down
        await new Promise<void>((res) => client.once("close", () => res()));
      } finally {
        try { lock.release(); } catch {}
      }
    } catch (e: any) {
      if (!o.signal?.aborted) console.error(`[mail] ${e.message}; reconnecting in ${backoff}s`);
    } finally {
      o.signal?.removeEventListener("abort", onAbort);
    }
    await sleep(backoff * 1000, o.signal);
    backoff = Math.min(backoff * 2, 300);
  }
}
