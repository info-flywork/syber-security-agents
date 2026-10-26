export type Severity = "critical" | "high" | "info";
export type Kind = "uptime" | "https" | "redirect" | "script" | "exposed" | "headers" | "dns";

export interface SiteConfig {
  /** URL'den türetilen kısa kimlik (ör. "ornek-com") */
  id: string;
  name: string;
  /** Sadece origin: https://ornek.com */
  origin: string;
  /** Kontrol edilecek sayfalar (yol), en az "/" */
  pages: string[];
  /** Siteye özel ek hassas dosya yolları */
  extraPaths: string[];
  emails: string[];
  intervalMin: 5 | 15 | 60;
  paused: boolean;
  createdAt: string;
  /** Ekleyen kişi bu siteyi izleme yetkisi olduğunu onayladı */
  ownerConfirmed: true;
}

export interface CheckResult {
  id: string;
  kind: Kind;
  title: string;
  ok: boolean;
  severity: Severity;
  detail: string;
  /** Kontrol yapılamadı (ağ hatası vb.) — önceki durum korunur */
  skip?: boolean;
}

export interface Incident extends CheckResult {
  since: string;
  fails: number;
  alerted: boolean;
}

export interface SiteEvent {
  at: string;
  type: "opened" | "resolved" | "notice";
  kind: Kind;
  title: string;
  detail: string;
  severity: Severity;
}

export interface RunPoint {
  at: string;
  up: boolean;
  failing: number;
  ms: number;
}

export interface SiteState {
  incidents: Record<string, Incident>;
  dnsBaseline: Record<string, string[]> | null;
  scriptBaseline: Record<string, string[]>;
  lastRun: string | null;
  lastDurationMs: number;
  lastResults: CheckResult[];
  lastMail: { ok: boolean; at: string; error?: string } | null;
  /** Son 24 saatlik kontrol noktaları (erişilebilirlik yüzdesi için) */
  history: RunPoint[];
  /** Son 200 olay (açıldı / düzeldi / bildirim) */
  events: SiteEvent[];
  runs: number;
}

export type FetchFn = (input: string, init?: RequestInit) => Promise<Response>;
