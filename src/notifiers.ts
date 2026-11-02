import nodemailer from "nodemailer";
import type { Item, Notifier } from "./types.js";
import { isDry } from "./flags.js";
import { safeHost, sleep } from "./util.js";

const env = (k: string) => process.env[k];

/**
 * JSON POST with retries on network errors, 429 and 5xx (honouring Retry-After).
 * Errors only ever name the host: webhook URLs and bot tokens live in the path and must not reach logs.
 */
export async function post(
  url: string,
  body: unknown,
  headers: Record<string, string> = {},
  opts: { attempts?: number; baseMs?: number } = {},
): Promise<void> {
  const attempts = opts.attempts ?? 3;
  const baseMs = opts.baseMs ?? 1000;
  for (let n = 1; ; n++) {
    let r: Response;
    try {
      r = await fetch(url, {
        method: "POST",
        headers: { "content-type": "application/json", ...headers },
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(15_000),
      });
    } catch (e: any) {
      if (n >= attempts) throw new Error(`${safeHost(url)} unreachable (${e.cause?.code ?? e.message})`);
      await sleep(baseMs * n);
      continue;
    }
    if (r.ok) {
      await r.body?.cancel();
      return;
    }
    const retriable = r.status === 429 || r.status >= 500;
    if (!retriable || n >= attempts) {
      throw new Error(`${safeHost(url)} -> HTTP ${r.status} ${(await r.text()).slice(0, 200)}`);
    }
    await r.body?.cancel();
    const ra = Number(r.headers.get("retry-after"));
    await sleep(Math.min(ra > 0 ? ra * 1000 : baseMs * n * 2, 15_000));
  }
}

/** Slack mrkdwn treats & < > specially (<!channel>, <url|label>); feed/mail text is untrusted. */
export const slackEscape = (t: string) => t.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");

/** WhatsApp template variables reject newlines, tabs and long runs of spaces, and cap at 1024 chars. */
export const waText = (t: string) => t.replace(/\s*\n\s*/g, " | ").replace(/\s{2,}/g, " ").slice(0, 900);

export function buildNotifiers(): Notifier[] {
  const out: Notifier[] = [];

  if (isDry()) {
    return [{ name: "console", send: async (_i, t) => console.log("\n--- ALERT ---\n" + t) }];
  }

  if (env("SLACK_WEBHOOK_URL")) {
    out.push({
      name: "slack",
      send: (_i, t) => post(env("SLACK_WEBHOOK_URL")!, { text: slackEscape(t) }),
    });
  }

  if (env("TELEGRAM_BOT_TOKEN") && env("TELEGRAM_CHAT_ID")) {
    out.push({
      name: "telegram",
      send: (_i, t) =>
        post(`https://api.telegram.org/bot${env("TELEGRAM_BOT_TOKEN")}/sendMessage`, {
          chat_id: env("TELEGRAM_CHAT_ID"),
          text: t.slice(0, 4000), // Telegram limit is 4096
          disable_web_page_preview: true,
        }),
    });
  }

  if (env("SMTP_HOST") && env("MAIL_TO")) {
    const port = Number(env("SMTP_PORT") ?? 587);
    const tx = nodemailer.createTransport({
      host: env("SMTP_HOST"),
      port,
      secure: port === 465, // implicit TLS; 587/25 use STARTTLS
      auth: env("SMTP_USER") ? { user: env("SMTP_USER")!, pass: env("SMTP_PASS")! } : undefined,
    });
    out.push({
      name: "email",
      send: async (i, t) => {
        await tx.sendMail({
          from: env("MAIL_FROM") ?? env("SMTP_USER"),
          to: env("MAIL_TO"),
          subject: `${i.security ? "[SECURITY] " : ""}${i.source}: ${i.title}`.replace(/[\r\n]+/g, " "),
          text: t,
        });
      },
    });
  }

  // WhatsApp Cloud API. Business-initiated messages outside a 24h chat window
  // MUST use an approved template with one body variable ({{1}}).
  if (env("WA_TOKEN") && env("WA_PHONE_ID") && env("WA_TO") && env("WA_TEMPLATE")) {
    const version = env("WA_API_VERSION") ?? "v25.0";
    out.push({
      name: "whatsapp",
      send: (_i, t) =>
        post(
          `https://graph.facebook.com/${version}/${env("WA_PHONE_ID")}/messages`,
          {
            messaging_product: "whatsapp",
            to: env("WA_TO"),
            type: "template",
            template: {
              name: env("WA_TEMPLATE"),
              language: { code: env("WA_LANG") ?? "en" },
              components: [{ type: "body", parameters: [{ type: "text", text: waText(t) }] }],
            },
          },
          { authorization: `Bearer ${env("WA_TOKEN")}` },
        ),
    });
  }

  return out;
}

const fmt = (iso?: string) => {
  if (!iso) return "n/a";
  const utc = iso.replace(".000Z", "Z");
  try {
    const tz = process.env.DISPLAY_TZ ?? "UTC";
    return `${new Date(iso).toLocaleString("en-GB", { timeZone: tz, hour12: false, dateStyle: "medium", timeStyle: "medium" })} (${utc})`;
  } catch {
    return utc; // bad DISPLAY_TZ must never stop an alert from going out
  }
};

export function render(i: Item): string {
  const latency = i.publishedAt ? Math.round((+new Date(i.detectedAt) - +new Date(i.publishedAt)) / 1000) : null;
  return [
    `${i.security ? "🚨 SECURITY" : "📦 RELEASE"} | ${i.source}`,
    i.title,
    i.summary ? `\n${i.summary}` : "",
    `\nPublished: ${fmt(i.publishedAt)}`,
    `Detected:  ${fmt(i.detectedAt)}${latency != null && latency >= 0 ? `  (+${latency}s)` : ""}`,
    i.url,
  ]
    .filter(Boolean)
    .join("\n");
}
