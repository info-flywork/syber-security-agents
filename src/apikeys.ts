/**
 * Varlık API anahtarları ve istek imzası.
 *
 * - Site ID (public): sg_<mod>_pk_… — istekte açıkça gönderilir, anahtarı bulmaya yarar.
 * - Secret: sg_<mod>_sk_… — sadece oluşturulduğunda bir kez gösterilir; ağda gönderilmez, veritabanında saklanmaz.
 *
 * İstemci secret'tan tek yönlü bir imza anahtarı türetir: k = HMAC-SHA256(secret, "sitegozcu/v1/signing").
 * Sunucu sadece k'yi saklar, o da APP_SECRET ile şifreli. Her istek k ile imzalanır:
 *
 *   imza = HMAC-SHA256(k, "v1\n<zaman>\n<nonce>\n<METHOD>\n<yol>\n<sha256(gövde)>")
 *
 * Başlıklar: X-SG-Site, X-SG-Timestamp (unix saniye), X-SG-Nonce, X-SG-Signature: v1=<hex>
 */
import { createHash, createHmac, randomBytes } from "node:crypto";
import type { Db, Q } from "./db";
import { decryptSecret, encryptSecret, safeEqual } from "./security";

export type KeyMode = "live" | "test";
export const KEY_MODES: KeyMode[] = ["live", "test"];
export const SIGNING_CONTEXT = "sitegozcu/v1/signing";
export const TIMESTAMP_WINDOW_S = 300;

const PUBLIC_RE = /^sg_(live|test)_pk_[A-Za-z0-9_-]{16,64}$/;
const ENC_CONTEXT = "api-signing";

const rand = (bytes: number) => randomBytes(bytes).toString("base64url");

export function newCredentials(mode: KeyMode): { publicId: string; secret: string } {
  return { publicId: `sg_${mode}_pk_${rand(16)}`, secret: `sg_${mode}_sk_${rand(32)}` };
}

export const isPublicId = (s: string) => PUBLIC_RE.test(s);

export function deriveSigningKey(secret: string): Buffer {
  return createHmac("sha256", secret).update(SIGNING_CONTEXT).digest();
}

export function canonicalString(timestamp: string, nonce: string, method: string, path: string, body: Uint8Array | string): string {
  const bodyHash = createHash("sha256").update(body).digest("hex");
  return ["v1", timestamp, nonce, method.toUpperCase(), path, bodyHash].join("\n");
}

export function signWithKey(signingKey: Buffer, canonical: string): string {
  return createHmac("sha256", signingKey).update(canonical).digest("hex");
}

/** İstemci tarafı imzalama (testler ve belgeler için; PHP/Node istemcileri aynısını yapar). */
export function signRequest(
  o: { publicId: string; secret: string; method?: string; path?: string; body: string; timestamp?: number; nonce?: string },
): Record<string, string> {
  const ts = String(o.timestamp ?? Math.floor(Date.now() / 1000));
  const nonce = o.nonce ?? rand(16);
  const sig = signWithKey(deriveSigningKey(o.secret), canonicalString(ts, nonce, o.method ?? "POST", o.path ?? "/api/v1/events", o.body));
  return { "x-sg-site": o.publicId, "x-sg-timestamp": ts, "x-sg-nonce": nonce, "x-sg-signature": `v1=${sig}` };
}

export function verifySignature(signingKey: Buffer, canonical: string, header: string): boolean {
  const m = header.match(/^v1=([0-9a-f]{64})$/);
  return !!m && safeEqual(signWithKey(signingKey, canonical), m[1]);
}

// ——— Veritabanı ———

export interface SiteKey {
  id: string;
  mode: KeyMode;
  publicId: string;
  secretHint: string;
  createdAt: Date;
  rotatedAt: Date | null;
  lastUsedAt: Date | null;
}

const KEY_SELECT = `SELECT id, mode, public_id AS "publicId", secret_hint AS "secretHint", created_at AS "createdAt",
  rotated_at AS "rotatedAt", last_used_at AS "lastUsedAt" FROM site_keys`;

export async function listActiveKeys(db: Q, siteUuid: string): Promise<SiteKey[]> {
  const { rows } = await db.query<SiteKey>(`${KEY_SELECT} WHERE site_uuid = $1 AND revoked_at IS NULL ORDER BY mode`, [siteUuid]);
  return rows;
}

const hint = (secret: string) => secret.slice(-4);

/** Yeni anahtar: o modda etkin anahtar varsa null (önce iptal ya da yenileme). */
export async function createKey(db: Db, siteUuid: string, mode: KeyMode, appSecret: string, userId: string | null): Promise<{ key: SiteKey; secret: string } | null> {
  const { publicId, secret } = newCredentials(mode);
  const { rows } = await db.query<SiteKey>(
    `INSERT INTO site_keys (site_uuid, mode, public_id, signing_key_enc, secret_hint, created_by) VALUES ($1, $2, $3, $4, $5, $6)
     ON CONFLICT (site_uuid, mode) WHERE revoked_at IS NULL DO NOTHING
     RETURNING id, mode, public_id AS "publicId", secret_hint AS "secretHint", created_at AS "createdAt", rotated_at AS "rotatedAt", last_used_at AS "lastUsedAt"`,
    [siteUuid, mode, publicId, encryptSecret(deriveSigningKey(secret).toString("base64"), appSecret, ENC_CONTEXT), hint(secret), userId],
  );
  return rows[0] ? { key: rows[0], secret } : null;
}

/** Secret'ı yenile: Site ID aynı kalır, eski secret anında geçersiz olur. */
export async function rotateKey(db: Q, siteUuid: string, mode: KeyMode, appSecret: string): Promise<{ key: SiteKey; secret: string } | null> {
  const secret = newCredentials(mode).secret;
  const { rows } = await db.query<SiteKey>(
    `UPDATE site_keys SET signing_key_enc = $3, secret_hint = $4, rotated_at = now()
     WHERE site_uuid = $1 AND mode = $2 AND revoked_at IS NULL
     RETURNING id, mode, public_id AS "publicId", secret_hint AS "secretHint", created_at AS "createdAt", rotated_at AS "rotatedAt", last_used_at AS "lastUsedAt"`,
    [siteUuid, mode, encryptSecret(deriveSigningKey(secret).toString("base64"), appSecret, ENC_CONTEXT), hint(secret)],
  );
  if (!rows[0]) return null;
  // Eski secret'la imzalanmış ama henüz işlenmemiş istekler kabul edilmesin
  await db.query("DELETE FROM ingest_nonces WHERE key_id = $1", [rows[0].id]);
  return { key: rows[0], secret };
}

/** İptal: Site ID ve secret kalıcı olarak geçersiz olur; yeni anahtar yeni Site ID ile gelir. */
export async function revokeKey(db: Q, siteUuid: string, mode: KeyMode): Promise<boolean> {
  const r = await db.query("UPDATE site_keys SET revoked_at = now(), signing_key_enc = NULL WHERE site_uuid = $1 AND mode = $2 AND revoked_at IS NULL", [siteUuid, mode]);
  return (r.rowCount ?? 0) > 0;
}

export interface ActiveKey {
  id: string;
  siteUuid: string;
  mode: KeyMode;
  signingKey: Buffer;
}

export async function findActiveKey(db: Q, publicId: string, appSecret: string): Promise<ActiveKey | null> {
  if (!isPublicId(publicId)) return null;
  const { rows } = await db.query<{ id: string; site_uuid: string; mode: KeyMode; signing_key_enc: string }>(
    "SELECT id, site_uuid, mode, signing_key_enc FROM site_keys WHERE public_id = $1 AND revoked_at IS NULL AND signing_key_enc IS NOT NULL",
    [publicId],
  );
  const r = rows[0];
  if (!r) return null;
  return { id: r.id, siteUuid: r.site_uuid, mode: r.mode, signingKey: Buffer.from(decryptSecret(r.signing_key_enc, appSecret, ENC_CONTEXT), "base64") };
}

/** Nonce'u kaydet; daha önce kullanıldıysa false (tekrar oynatma). */
export async function claimNonce(db: Q, keyId: string, nonce: string): Promise<boolean> {
  const r = await db.query("INSERT INTO ingest_nonces (key_id, nonce) VALUES ($1, $2) ON CONFLICT DO NOTHING", [keyId, nonce]);
  return (r.rowCount ?? 0) > 0;
}

export async function touchKey(db: Q, keyId: string): Promise<void> {
  await db.query("UPDATE site_keys SET last_used_at = now() WHERE id = $1", [keyId]);
}

/** Zaman penceresinin iki katından eski nonce'lar artık gerekmez. */
export async function pruneNonces(db: Q): Promise<void> {
  await db.query(`DELETE FROM ingest_nonces WHERE at < now() - interval '${TIMESTAMP_WINDOW_S * 2} seconds'`);
}
