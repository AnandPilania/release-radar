export interface Item {
  id: string;
  source: string;
  title: string;
  url: string;
  summary?: string;
  publishedAt?: string; // ISO, as reported by the source
  detectedAt: string;   // ISO, when we first saw it
  security: boolean;
  /** Cross-channel dedupe key (poll, webhook and mail can all report the same release). */
  key?: string;
}

export interface SourceCfg {
  name: string;
  type: "feed" | "kev";
  url: string;
  notify: "all" | "security";
}

export interface MailRule {
  name: string;
  from?: string;            // substring of From header
  listId?: string;          // substring of List-Id header
  subjectContains?: string;
  notify?: "all" | "security";
  /** Require a passing, From-aligned DKIM/DMARC result in the receiving server's Authentication-Results. */
  requireAuth?: boolean;
}

export interface Config {
  webhook?: { port: number; notify: "all" | "security" };
  mail?: { rules: MailRule[] };
  pollSeconds: number;
  securityKeywords: string[];
  sources: SourceCfg[];
}

export interface Notifier {
  name: string;
  send(item: Item, text: string): Promise<void>;
}
