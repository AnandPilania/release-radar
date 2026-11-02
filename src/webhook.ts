import http from "node:http";
import { createHmac, timingSafeEqual } from "node:crypto";
import type { Item } from "./types.js";
import { canonGithub, isSecurity, strip } from "./util.js";

const MAX_BODY = 1_000_000; // 1 MB

export function verifySignature(secret: string, raw: Buffer, header?: string): boolean {
  if (!header?.startsWith("sha256=")) return false;
  const given = Buffer.from(header.slice(7), "hex");
  const want = createHmac("sha256", secret).update(raw).digest();
  return given.length === want.length && timingSafeEqual(given, want);
}

/** Map a GitHub webhook payload to an Item. Returns null for events we ignore. */
export function toItem(event: string, p: any, keywords: string[]): Item | null {
  const now = new Date().toISOString();
  const repo = p.repository?.full_name ?? "unknown/repo";

  if (event === "release" && (p.action === "published" || p.action === "released")) {
    const r = p.release;
    if (r.draft) return null;
    const body = strip(String(r.body ?? "")).slice(0, 400);
    const title = `${repo} ${r.name || r.tag_name}`;
    return {
      id: `gh-release:${r.id}`,
      key: canonGithub(r.html_url),
      source: `GitHub ${repo}`,
      title,
      url: r.html_url,
      summary: body,
      publishedAt: r.published_at ?? r.created_at,
      detectedAt: now,
      security: isSecurity(`${title} ${body}`, keywords),
    };
  }

  if (event === "repository_advisory" && (p.action === "published" || p.action === "reported")) {
    const a = p.repository_advisory ?? p.advisory ?? {};
    return {
      id: `gh-advisory:${a.ghsa_id}`,
      key: `advisory:${a.ghsa_id}`,
      source: `GitHub advisory ${repo}`,
      title: `${a.cve_id ? a.cve_id + " " : ""}${a.summary ?? a.ghsa_id}${a.severity ? ` [${a.severity}]` : ""}`,
      url: a.html_url ?? p.repository?.html_url,
      summary: strip(String(a.description ?? "")).slice(0, 400),
      publishedAt: a.published_at ?? a.created_at,
      detectedAt: now,
      security: true,
    };
  }

  if (event === "create" && p.ref_type === "tag") {
    const url = `${p.repository.html_url}/releases/tag/${p.ref}`;
    return {
      id: `gh-tag:${repo}:${p.ref}`,
      key: canonGithub(url),
      source: `GitHub ${repo}`,
      title: `${repo} new tag ${p.ref}`,
      url,
      publishedAt: now,
      detectedAt: now,
      security: false,
    };
  }
  return null;
}

export function startWebhook(o: {
  port: number;
  host?: string;
  secret: string;
  keywords: string[];
  onItem: (item: Item) => Promise<void>;
}): http.Server {
  const srv = http.createServer((req, res) => {
    const path = (req.url ?? "").split("?")[0];
    if (req.method === "GET" && path === "/healthz") return void res.writeHead(200).end("ok");
    if (req.method !== "POST" || path !== "/webhook/github") return void res.writeHead(404).end();

    const chunks: Buffer[] = [];
    let size = 0;
    let aborted = false;
    req.on("error", () => (aborted = true));
    req.on("data", (c: Buffer) => {
      if (aborted) return;
      size += c.length;
      if (size > MAX_BODY) {
        aborted = true;
        res.writeHead(413, { connection: "close" }).end("too large");
        req.destroy();
      } else chunks.push(c);
    });
    req.on("end", () => {
      if (aborted) return;
      const raw = Buffer.concat(chunks);
      if (!verifySignature(o.secret, raw, req.headers["x-hub-signature-256"] as string | undefined)) {
        return void res.writeHead(401).end("bad signature");
      }
      const event = String(req.headers["x-github-event"] ?? "");
      if (event === "ping") return void res.writeHead(200).end("pong");
      res.writeHead(202).end("accepted"); // ack fast; GitHub times out at 10s
      try {
        const item = toItem(event, JSON.parse(raw.toString("utf8")), o.keywords);
        if (item) o.onItem(item).catch((e) => console.error("[webhook]", e.message));
      } catch (e: any) {
        console.error("[webhook] bad payload:", e.message);
      }
    });
  });
  srv.listen(o.port, o.host ?? "0.0.0.0", () => {
    const a = srv.address();
    console.log(`webhook listening on :${typeof a === "object" && a ? a.port : o.port}  POST /webhook/github`);
  });
  return srv;
}
