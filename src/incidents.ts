/**
 * Olay takibi — sadece durum DEĞİŞTİĞİNDE uyarı üretir (açıldı / düzeldi).
 */
import { DOWN_THRESHOLD } from "./defaults";
import type { CheckResult, Incident } from "./types";

export interface Evaluation {
  incidents: Record<string, Incident>;
  opened: Incident[];
  resolved: Incident[];
}

export function evaluate(prev: Record<string, Incident>, results: CheckResult[], now: string): Evaluation {
  const incidents: Record<string, Incident> = { ...prev };
  const opened: Incident[] = [];
  const resolved: Incident[] = [];
  for (const r of results) {
    if (r.skip) continue; // kontrol edilemedi: olay açılmaz, kapanmaz
    const cur = incidents[r.id];
    if (!r.ok) {
      const next: Incident = cur ? { ...cur, detail: r.detail, fails: cur.fails + 1 } : { ...r, since: now, fails: 1, alerted: false };
      const need = r.kind === "uptime" ? DOWN_THRESHOLD : 1;
      if (!next.alerted && next.fails >= need) {
        next.alerted = true;
        opened.push(next);
      }
      incidents[r.id] = next;
    } else if (cur) {
      if (cur.alerted) resolved.push({ ...cur, ok: true, detail: r.detail });
      delete incidents[r.id];
    }
  }
  return { incidents, opened, resolved };
}

/** E-posta gerektiren olaylar: bilgi seviyesindekiler (güvenlik başlıkları) sadece panelde görünür. */
export function mailworthy<T extends { severity: string }>(items: T[]): T[] {
  return items.filter((i) => i.severity !== "info");
}

export function minutesSince(iso: string, now: string): number {
  return Math.max(0, Math.round((Date.parse(now) - Date.parse(iso)) / 60000));
}
