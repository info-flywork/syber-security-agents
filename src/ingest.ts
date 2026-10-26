/**
 * POST /api/v1/events — uygulamalardan imzalı olay alma.
 *
 * Sıra: IP sınırı → başlıklar → zaman penceresi (±5 dk) → anahtar → anahtar sınırı → imza → nonce (tekrar) → gövde.
 * Olay her zaman anahtarın bağlı olduğu varlığa yazılır; gövdede varlık seçilemez.
 * Nonce imza doğrulandıktan sonra kaydedilir: imzasız istekler başkasının nonce'unu tüketemez.
 */
import { canonicalString, claimNonce, findActiveKey, touchKey, verifySignature, TIMESTAMP_WINDOW_S } from "./apikeys";
import { insertEvents, parseEvents } from "./app-events";
import { RateLimiter } from "./auth";
import type { Db } from "./db";

export const INGEST_PATH = "/api/v1/events";
const MAX_BODY = 64_000;

export interface IngestDeps {
  db: Db;
  appSecret: string;
  /** Testlerde sınırları küçültmek için */
  limits?: { perIp?: number; perKey?: number };
}

export function createIngest(deps: IngestDeps) {
  const ipLimit = new RateLimiter(deps.limits?.perIp ?? 300, 60_000);
  const keyLimit = new RateLimiter(deps.limits?.perKey ?? 120, 60_000);

  const json = (status: number, body: Record<string, unknown>, extra: Record<string, string> = {}) =>
    new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", "x-content-type-options": "nosniff", ...extra } });
  // Anahtarın var olup olmadığı dışarıdan anlaşılmasın: bulunamayan anahtar ve hatalı imza aynı cevabı alır
  const badSig = () => json(401, { error: "imza geçersiz" });

  return async function ingest(req: Request, ip: string | null): Promise<Response> {
    if (req.method !== "POST") return json(405, { error: "sadece POST" }, { allow: "POST" });
    if (!ipLimit.allow(`ip:${ip}`)) return json(429, { error: "çok fazla istek" }, { "retry-after": "60" });

    const site = req.headers.get("x-sg-site") ?? "";
    const ts = req.headers.get("x-sg-timestamp") ?? "";
    const nonce = req.headers.get("x-sg-nonce") ?? "";
    const sig = req.headers.get("x-sg-signature") ?? "";
    if (!site || !/^\d{9,11}$/.test(ts) || !/^[A-Za-z0-9_-]{16,64}$/.test(nonce) || !sig) {
      return json(400, { error: "X-SG-Site, X-SG-Timestamp, X-SG-Nonce ve X-SG-Signature başlıkları gerekli" });
    }
    const skew = Math.abs(Date.now() / 1000 - Number(ts));
    if (skew > TIMESTAMP_WINDOW_S) return json(401, { error: "zaman damgası 5 dakikalık pencerenin dışında; sunucu saatini kontrol edin" });

    const body = new Uint8Array(await req.arrayBuffer());
    if (body.length > MAX_BODY) return json(413, { error: "gövde çok büyük" });

    const key = await findActiveKey(deps.db, site, deps.appSecret);
    if (!key) return badSig();
    if (!keyLimit.allow(key.id)) return json(429, { error: "bu anahtar için çok fazla istek" }, { "retry-after": "60" });
    const path = new URL(req.url).pathname;
    if (!verifySignature(key.signingKey, canonicalString(ts, nonce, req.method, path, body), sig)) return badSig();
    if (!(await claimNonce(deps.db, key.id, nonce))) return json(409, { error: "bu istek daha önce alındı (tekrar oynatma)" });

    let parsed: unknown;
    try {
      parsed = JSON.parse(new TextDecoder().decode(body));
    } catch {
      return json(400, { error: "gövde geçerli JSON değil" });
    }
    const r = parseEvents(parsed);
    if (!r.ok) return json(400, { error: r.error });
    await insertEvents(deps.db, key.siteUuid, key.id, key.mode, r.events);
    await touchKey(deps.db, key.id);
    return json(202, { accepted: r.events.length, mode: key.mode });
  };
}
