/**
 * Site Gözcü Node.js istemcisi — tek dosya, bağımlılık yok (Node 18+).
 *
 * Uygulamanızdaki güvenlik olaylarını Site Gözcü paneline imzalı olarak gönderir.
 * Secret ağda gönderilmez: her istek secret'tan türetilen anahtarla HMAC-SHA256 imzalanır.
 * Hiçbir zaman hata fırlatmaz; Site Gözcü'ye ulaşılamazsa false döner, uygulamanız etkilenmez.
 *
 *   import { SiteGozcu } from "./sitegozcu.mjs";
 *   const gozcu = SiteGozcu.fromEnv();
 *   await gozcu.failedLogin(email, { ip: req.ip });
 *
 * Bağlantı testi:  node --env-file=.env sitegozcu.mjs test
 */
import { createHash, createHmac, randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const VERSION = "1.0";
const PATH = "/api/v1/events";
const SIGNING_CONTEXT = "sitegozcu/v1/signing";

export function deriveSigningKey(secret) {
  return createHmac("sha256", secret).update(SIGNING_CONTEXT).digest();
}

export function signature(signingKey, ts, nonce, method, path, body) {
  const canonical = ["v1", ts, nonce, method.toUpperCase(), path, createHash("sha256").update(body).digest("hex")].join("\n");
  return createHmac("sha256", signingKey).update(canonical).digest("hex");
}

export class SiteGozcu {
  /** Son hatanın açıklaması (gönderim false döndüğünde) */
  lastError = null;
  #siteId;
  #signingKey;
  #endpoint;
  #timeoutMs;
  #fetch;

  /**
   * @param {{ siteId: string, secret: string, url: string, timeoutMs?: number, fetch?: typeof fetch }} o
   */
  constructor({ siteId, secret, url, timeoutMs = 2000, fetch: fetchFn = globalThis.fetch }) {
    if (!/^sg_(live|test)_pk_[A-Za-z0-9_-]{16,64}$/.test(siteId ?? "")) throw new Error("SITEGOZCU_SITE_ID geçersiz (sg_live_pk_… ya da sg_test_pk_… olmalı)");
    if (!/^sg_(live|test)_sk_[A-Za-z0-9_-]{20,}$/.test(secret ?? "")) throw new Error("SITEGOZCU_SECRET geçersiz (sg_live_sk_… ya da sg_test_sk_… olmalı)");
    if (!/^https?:\/\/[^/]+\/?$/.test(url ?? "")) throw new Error("SITEGOZCU_URL sadece şema ve alan adı olmalı, ör. https://panel.ornek.com");
    this.#siteId = siteId;
    this.#signingKey = deriveSigningKey(secret);
    this.#endpoint = url.replace(/\/$/, "") + PATH;
    this.#timeoutMs = timeoutMs;
    this.#fetch = fetchFn;
  }

  /** Ortam değişkenlerinden (ya da verilen .env dosyasından) kurar. */
  static fromEnv(envFile = null, env = process.env) {
    const vars = { ...env };
    if (envFile) {
      for (const line of readFileSync(envFile, "utf8").split(/\r?\n/)) {
        const m = line.match(/^\s*(SITEGOZCU_[A-Z_]+)\s*=\s*"?([^"]*)"?\s*$/);
        if (m && !vars[m[1]]) vars[m[1]] = m[2];
      }
    }
    return new SiteGozcu({ siteId: vars.SITEGOZCU_SITE_ID?.trim(), secret: vars.SITEGOZCU_SECRET?.trim(), url: vars.SITEGOZCU_URL?.trim() });
  }

  /** Başarısız giriş denemesi. user: denenen kullanıcı adı / e-posta. */
  failedLogin(user = null, extra = {}) {
    return this.event("auth.failed", { actor: user, ...extra });
  }

  /** Şüpheli istek (ör. SQL enjeksiyonu, yol geçişi). */
  suspiciousRequest(reason, extra = {}) {
    return this.event("request.suspicious", { message: reason, ...extra });
  }

  /** Yetkisiz erişim denemesi. resource: erişilmeye çalışılan sayfa / kaynak. */
  accessDenied(resource = null, extra = {}) {
    return this.event("access.denied", { path: resource, ...extra });
  }

  /** Uygulama hatası. Error verilirse ad, mesaj ve ilk yığın satırının konumu gönderilir (tam yığın izi gönderilmez). */
  appError(error, extra = {}) {
    let message = String(error);
    if (error instanceof Error) {
      const where = error.stack?.split("\n")[1]?.trim().replace(/^at\s+/, "") ?? "";
      message = `${error.name}: ${error.message}${where ? ` (${where.split("/").pop()})` : ""}`;
    }
    return this.event("app.error", { message, ...extra });
  }

  /** Bağlantı testi: olay yazmaz, sadece anahtarın çalıştığını doğrular ve panelde "Bağlandı" gösterir. */
  ping() {
    return this.send([]);
  }

  /** Tek olay. fields: actor, ip, path, message, severity (info|high|critical), meta, occurred_at (ISO 8601). */
  event(type, fields = {}) {
    const e = { type };
    for (const [k, v] of Object.entries(fields)) if (v !== null && v !== undefined && v !== "") e[k] = v;
    return this.send([e]);
  }

  /** En fazla 50 olayı tek istekte gönderir. Promise<boolean>; asla reddedilmez. */
  async send(events) {
    this.lastError = null;
    try {
      const body = JSON.stringify({ events, client: `node/${VERSION}` });
      const ts = String(Math.floor(Date.now() / 1000));
      const nonce = randomBytes(16).toString("base64url");
      const res = await this.#fetch(this.#endpoint, {
        method: "POST",
        redirect: "manual",
        signal: AbortSignal.timeout(this.#timeoutMs),
        headers: {
          "content-type": "application/json",
          "user-agent": `SiteGozcu-Node/${VERSION}`,
          "x-sg-site": this.#siteId,
          "x-sg-timestamp": ts,
          "x-sg-nonce": nonce,
          "x-sg-signature": `v1=${signature(this.#signingKey, ts, nonce, "POST", PATH, body)}`,
        },
        body,
      });
      if (res.status === 202) return true;
      let detail = "";
      try {
        detail = (await res.json()).error ?? "";
      } catch {
        /* JSON değil */
      }
      this.lastError = `HTTP ${res.status}${detail ? `: ${detail}` : ""}`;
      return false;
    } catch (e) {
      this.lastError = e?.cause?.message ?? e?.message ?? String(e);
      return false;
    }
  }
}

// Komut satırı: node --env-file=.env sitegozcu.mjs test
if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  if (process.argv[2] !== "test") {
    console.error("Kullanım: node --env-file=.env sitegozcu.mjs test");
    process.exit(2);
  }
  let gozcu;
  try {
    gozcu = SiteGozcu.fromEnv();
  } catch (e) {
    console.error(`Ayar hatası: ${e.message}`);
    process.exit(1);
  }
  if (await gozcu.ping()) {
    console.log('Bağlantı başarılı: Site Gözcü panelinde bu varlık artık "Bağlandı" görünür.');
  } else {
    console.error(`Bağlantı başarısız: ${gozcu.lastError}`);
    process.exit(1);
  }
}
