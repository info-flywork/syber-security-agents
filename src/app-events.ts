/**
 * Uygulamalardan (PHP / Node istemcileri) gelen güvenlik olayları: doğrulama, saklama, özet ve risk katkısı.
 */
import { isIP } from "node:net";
import type { KeyMode } from "./apikeys";
import type { Q } from "./db";
import type { Severity } from "./types";

export type AppEventType = "auth.failed" | "request.suspicious" | "access.denied" | "app.error";

export const APP_EVENT_TYPES: Record<AppEventType, { label: string; severity: Severity }> = {
  "auth.failed": { label: "Başarısız giriş", severity: "info" },
  "request.suspicious": { label: "Şüpheli istek", severity: "high" },
  "access.denied": { label: "Yetkisiz erişim denemesi", severity: "high" },
  "app.error": { label: "Uygulama hatası", severity: "info" },
};

export const MAX_EVENTS_PER_REQUEST = 50;
/** Risk puanına katkı (son 24 saat, sadece live): olay başına ağırlık, varlık başına en fazla 50 puan. */
const EVENT_WEIGHT: Record<Severity, number> = { critical: 15, high: 5, info: 0.5 };
export const APP_RISK_CAP = 50;

export interface IncomingEvent {
  type: AppEventType;
  severity: Severity;
  message: string | null;
  ip: string | null;
  path: string | null;
  actor: string | null;
  meta: Record<string, unknown> | null;
  occurredAt: string;
}

export interface AppEvent extends IncomingEvent {
  mode: KeyMode;
  receivedAt: string;
}

const str = (v: unknown, max: number): string | null => {
  if (v === undefined || v === null || v === "") return null;
  if (typeof v !== "string") throw new Error("metin olmalı");
  // Kontrol karakterleri temizlenir; uzunluk sınırlanır
  return v.replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, "").slice(0, max);
};

/** İstek gövdesi: { "events": [ … ] } ya da tek olay nesnesi. Boş liste = bağlantı testi (ping). */
export function parseEvents(body: unknown, now = Date.now()): { ok: true; events: IncomingEvent[] } | { ok: false; error: string } {
  if (!body || typeof body !== "object" || Array.isArray(body)) return { ok: false, error: "gövde JSON nesnesi olmalı" };
  const b = body as Record<string, unknown>;
  const list = "events" in b ? b.events : [b];
  if (!Array.isArray(list)) return { ok: false, error: "events bir dizi olmalı" };
  if (list.length > MAX_EVENTS_PER_REQUEST) return { ok: false, error: `istek başına en fazla ${MAX_EVENTS_PER_REQUEST} olay` };
  const out: IncomingEvent[] = [];
  for (let i = 0; i < list.length; i++) {
    const e = list[i] as Record<string, unknown>;
    const at = `events[${i}]`;
    if (!e || typeof e !== "object" || Array.isArray(e)) return { ok: false, error: `${at}: nesne olmalı` };
    if (typeof e.type !== "string" || !(e.type in APP_EVENT_TYPES)) return { ok: false, error: `${at}.type: ${Object.keys(APP_EVENT_TYPES).join(", ")} olmalı` };
    const type = e.type as AppEventType;
    let severity = APP_EVENT_TYPES[type].severity;
    if (e.severity !== undefined) {
      if (e.severity !== "info" && e.severity !== "high" && e.severity !== "critical") return { ok: false, error: `${at}.severity: info, high ya da critical olmalı` };
      severity = e.severity;
    }
    let occurredAt = new Date(now).toISOString();
    if (e.occurred_at !== undefined) {
      const t = typeof e.occurred_at === "string" ? Date.parse(e.occurred_at) : NaN;
      if (!Number.isFinite(t) || t < now - 24 * 3600_000 || t > now + 5 * 60_000) return { ok: false, error: `${at}.occurred_at: son 24 saat içinde ISO 8601 zaman olmalı` };
      occurredAt = new Date(t).toISOString();
    }
    let ip: string | null;
    let meta: Record<string, unknown> | null = null;
    try {
      ip = str(e.ip, 64);
      if (ip && !isIP(ip)) return { ok: false, error: `${at}.ip: geçerli bir IP adresi olmalı` };
      if (e.meta !== undefined && e.meta !== null) {
        if (typeof e.meta !== "object" || Array.isArray(e.meta)) return { ok: false, error: `${at}.meta: nesne olmalı` };
        if (JSON.stringify(e.meta).length > 2000) return { ok: false, error: `${at}.meta: en fazla 2000 karakter` };
        meta = e.meta as Record<string, unknown>;
      }
      out.push({ type, severity, message: str(e.message, 500), ip, path: str(e.path, 300), actor: str(e.actor, 120), meta, occurredAt });
    } catch (err) {
      return { ok: false, error: `${at}: ${(err as Error).message}` };
    }
  }
  return { ok: true, events: out };
}

export async function insertEvents(db: Q, siteUuid: string, keyId: string, mode: KeyMode, events: IncomingEvent[]): Promise<void> {
  if (!events.length) return;
  const cols = 11;
  const values: unknown[] = [];
  const tuples = events.map((e, i) => {
    values.push(siteUuid, keyId, mode, e.type, e.severity, e.message, e.ip, e.path, e.actor, e.meta, e.occurredAt);
    return `(${Array.from({ length: cols }, (_, j) => `$${i * cols + j + 1}`).join(", ")})`;
  });
  await db.query(`INSERT INTO app_events (site_uuid, key_id, mode, type, severity, message, ip, path, actor, meta, occurred_at) VALUES ${tuples.join(", ")}`, values);
}

/** Varlık başına özet: son olaylar, 24 saatlik sayımlar (live) ve risk katkısı. */
export interface AppSummary {
  recent: AppEvent[];
  counts24: Record<AppEventType, number>;
  risk: number;
  lastAt: string | null;
  /** Etkin anahtarlardan biriyle en son geçerli istek (ping dahil) — "Bağlandı" durumu */
  lastSeen: string | null;
}

const emptyCounts = (): Record<AppEventType, number> => ({ "auth.failed": 0, "request.suspicious": 0, "access.denied": 0, "app.error": 0 });

export function appRisk(events: { severity: Severity; mode: KeyMode; occurredAt: string }[], now = Date.now()): number {
  const sum = events.filter((e) => e.mode === "live" && Date.parse(e.occurredAt) >= now - 24 * 3600_000).reduce((s, e) => s + EVENT_WEIGHT[e.severity], 0);
  return Math.min(APP_RISK_CAP, Math.round(sum));
}

export async function appSummaries(db: Q, siteUuids: string[], recentPerSite = 30): Promise<Map<string, AppSummary>> {
  const out = new Map<string, AppSummary>();
  for (const id of siteUuids) out.set(id, { recent: [], counts24: emptyCounts(), risk: 0, lastAt: null, lastSeen: null });
  if (!siteUuids.length) return out;
  const [recent, agg, seen] = await Promise.all([
    db.query<AppEvent & { site_uuid: string }>(
      `SELECT site_uuid, mode, type, severity, message, ip, path, actor, meta, occurred_at AS "occurredAt", received_at AS "receivedAt" FROM (
         SELECT *, row_number() OVER (PARTITION BY site_uuid ORDER BY occurred_at DESC) AS rn FROM app_events WHERE site_uuid = ANY($1)
       ) t WHERE rn <= $2 ORDER BY occurred_at DESC`,
      [siteUuids, recentPerSite],
    ),
    db.query<{ site_uuid: string; type: AppEventType; severity: Severity; n: number; last: Date }>(
      `SELECT site_uuid, type, severity, count(*)::int AS n, max(occurred_at) AS last FROM app_events
       WHERE site_uuid = ANY($1) AND mode = 'live' AND occurred_at >= now() - interval '24 hours'
       GROUP BY site_uuid, type, severity`,
      [siteUuids],
    ),
    db.query<{ site_uuid: string; last: Date }>(
      "SELECT site_uuid, max(last_used_at) AS last FROM site_keys WHERE site_uuid = ANY($1) AND revoked_at IS NULL AND last_used_at IS NOT NULL GROUP BY site_uuid",
      [siteUuids],
    ),
  ]);
  for (const r of seen.rows) out.get(r.site_uuid)!.lastSeen = r.last.toISOString();
  for (const r of recent.rows) {
    const s = out.get(r.site_uuid)!;
    const iso = (d: unknown) => (d instanceof Date ? d.toISOString() : String(d));
    s.recent.push({ ...r, occurredAt: iso(r.occurredAt), receivedAt: iso(r.receivedAt) });
    s.lastAt ??= iso(r.receivedAt);
  }
  const sums = new Map<string, number>();
  for (const r of agg.rows) {
    const s = out.get(r.site_uuid)!;
    s.counts24[r.type] += r.n;
    sums.set(r.site_uuid, (sums.get(r.site_uuid) ?? 0) + r.n * EVENT_WEIGHT[r.severity]);
  }
  for (const [id, sum] of sums) out.get(id)!.risk = Math.min(APP_RISK_CAP, Math.round(sum));
  return out;
}

/** 30 günden eski olayları sil (günde bir). */
export async function pruneAppEvents(db: Q): Promise<void> {
  await db.query("DELETE FROM app_events WHERE received_at < now() - interval '30 days'");
}
