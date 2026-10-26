/**
 * Oturumlar: rastgele belirteç çerezde, SHA-256 özeti veritabanında (çalınan veritabanı yedeğiyle oturum açılamaz).
 * Aşamalar: totp (şifre doğru, kod bekleniyor) → full. 2FA kurmamış kullanıcı: setup → full.
 * Aşama değişince belirteç yenilenir (oturum sabitleme saldırısına karşı).
 * Form POST'ları ayrıca Origin kontrolüyle korunur (CSRF).
 */
import type { Q } from "./db";
import { randomToken, sha256 } from "./security";

export type Stage = "totp" | "setup" | "full";

/** Tam oturum: 12 saat işlem yapılmazsa ya da en geç 7 günde biter. Ara aşamalar 15 dakika. */
const FULL_IDLE_MS = 12 * 3600_000;
const FULL_MAX_MS = 7 * 24 * 3600_000;
const PENDING_MS = 15 * 60_000;

export interface Session {
  tokenHash: string;
  userId: string;
  orgId: string | null;
  stage: Stage;
  email: string;
}

export const cookieName = (secure: boolean) => (secure ? "__Host-sg_session" : "sg_session");

export function sessionCookie(token: string, secure: boolean, clear = false): string {
  return `${cookieName(secure)}=${clear ? "" : token}; Path=/; HttpOnly; SameSite=Lax${secure ? "; Secure" : ""}; Max-Age=${clear ? 0 : FULL_MAX_MS / 1000}`;
}

export function readCookie(header: string | null, name: string): string | null {
  if (!header) return null;
  const m = header.split(/;\s*/).find((c) => c.startsWith(name + "="));
  return m ? m.slice(name.length + 1) || null : null;
}

export async function createSession(db: Q, userId: string, orgId: string | null, stage: Stage, ip: string | null, ua: string | null): Promise<string> {
  const token = randomToken();
  const ttl = stage === "full" ? FULL_MAX_MS : PENDING_MS;
  await db.query(
    "INSERT INTO sessions (token_hash, user_id, org_id, stage, expires_at, ip, user_agent) VALUES ($1, $2, $3, $4, now() + ($5 || ' milliseconds')::interval, $6, $7)",
    [sha256(token), userId, orgId, stage, String(ttl), ip, ua?.slice(0, 300) ?? null],
  );
  return token;
}

export async function loadSession(db: Q, token: string | null): Promise<Session | null> {
  if (!token || token.length > 100) return null;
  const { rows } = await db.query<Session & { lastSeen: Date }>(
    `SELECT s.token_hash AS "tokenHash", s.user_id AS "userId", s.org_id AS "orgId", s.stage, u.email, s.last_seen_at AS "lastSeen"
     FROM sessions s JOIN users u ON u.id = s.user_id
     WHERE s.token_hash = $1 AND s.expires_at > now()`,
    [sha256(token)],
  );
  const s = rows[0];
  if (!s) return null;
  if (s.stage === "full" && Date.now() - s.lastSeen.getTime() > FULL_IDLE_MS) {
    await destroySession(db, s.tokenHash);
    return null;
  }
  // Son görülme dakikada bir güncellenir
  if (Date.now() - s.lastSeen.getTime() > 60_000) await db.query("UPDATE sessions SET last_seen_at = now() WHERE token_hash = $1", [s.tokenHash]);
  return { tokenHash: s.tokenHash, userId: s.userId, orgId: s.orgId, stage: s.stage, email: s.email };
}

export async function destroySession(db: Q, tokenHash: string): Promise<void> {
  await db.query("DELETE FROM sessions WHERE token_hash = $1", [tokenHash]);
}

/** Aşama yükseltme: eski belirteç silinir, yenisi verilir. */
export async function upgradeSession(db: Q, s: Session, orgId: string | null, ip: string | null, ua: string | null): Promise<string> {
  await destroySession(db, s.tokenHash);
  return createSession(db, s.userId, orgId, "full", ip, ua);
}

export async function setSessionOrg(db: Q, tokenHash: string, orgId: string): Promise<void> {
  await db.query("UPDATE sessions SET org_id = $2 WHERE token_hash = $1", [tokenHash, orgId]);
}

/** Şifre değişince diğer cihazlardaki oturumlar kapanır. */
export async function destroyOtherSessions(db: Q, userId: string, keepHash: string): Promise<void> {
  await db.query("DELETE FROM sessions WHERE user_id = $1 AND token_hash <> $2", [userId, keepHash]);
}

/** POST istekleri yalnızca panelin kendi sayfasından gelebilir. */
export function sameOrigin(req: Request, publicOrigin: string): boolean {
  const origin = req.headers.get("origin");
  if (origin && origin !== "null") return origin === publicOrigin;
  // Origin yok ya da gizlilik nedeniyle "null": tarayıcının Sec-Fetch-Site başlığına güven
  return req.headers.get("sec-fetch-site") === "same-origin";
}

/** Basit bellek içi hız sınırı (tek süreç). Anahtar başına pencere içinde en fazla `max` deneme. */
export class RateLimiter {
  private hits = new Map<string, { n: number; reset: number }>();
  constructor(
    private max: number,
    private windowMs: number,
  ) {}
  allow(key: string, now = Date.now()): boolean {
    const h = this.hits.get(key);
    if (!h || h.reset < now) {
      if (this.hits.size > 10_000) this.sweep(now);
      this.hits.set(key, { n: 1, reset: now + this.windowMs });
      return true;
    }
    h.n++;
    return h.n <= this.max;
  }
  private sweep(now: number) {
    for (const [k, v] of this.hits) if (v.reset < now) this.hits.delete(k);
  }
}

/** Giriş sonrası yönlendirme: sadece panel içi basit yollar (açık yönlendirme açığı olmasın). */
export function safeNext(next: string | null): string {
  return next && /^\/[a-zA-Z0-9/_-]*$/.test(next) && !next.startsWith("//") ? next : "/";
}
