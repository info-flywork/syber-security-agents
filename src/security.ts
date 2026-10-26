/**
 * Şifre özeti (scrypt), TOTP (RFC 6238), rastgele belirteçler ve 2FA sırrı şifreleme. Sadece node:crypto.
 */
import { createCipheriv, createDecipheriv, createHash, createHmac, randomBytes, scrypt as scryptCb, timingSafeEqual, type ScryptOptions } from "node:crypto";

// ——— Şifre ———

/** OWASP önerisi: N=2^15, r=8, p=3 (~32 MiB bellek). Parametreler özetin içinde saklanır, ileride yükseltilebilir. */
const SCRYPT = { N: 2 ** 15, r: 8, p: 3, keylen: 64 };
export const PASSWORD_MIN = 12;
export const PASSWORD_MAX = 128;

function scrypt(pw: string, salt: Buffer, keylen: number, o: ScryptOptions): Promise<Buffer> {
  return new Promise((res, rej) => scryptCb(pw.normalize("NFKC"), salt, keylen, { ...o, maxmem: 256 * 1024 * 1024 }, (e, k) => (e ? rej(e) : res(k))));
}

export async function hashPassword(pw: string): Promise<string> {
  const salt = randomBytes(16);
  const key = await scrypt(pw, salt, SCRYPT.keylen, SCRYPT);
  return `scrypt$${SCRYPT.N}$${SCRYPT.r}$${SCRYPT.p}$${salt.toString("base64")}$${key.toString("base64")}`;
}

export async function verifyPassword(pw: string, stored: string): Promise<boolean> {
  const [alg, n, r, p, salt, key] = stored.split("$");
  if (alg !== "scrypt" || !key) return false;
  const expected = Buffer.from(key, "base64");
  const got = await scrypt(pw, Buffer.from(salt, "base64"), expected.length, { N: Number(n), r: Number(r), p: Number(p) });
  return got.length === expected.length && timingSafeEqual(got, expected);
}

/** Hesap yoksa da aynı süreyi harcamak için (e-posta varlığı zamanlamadan anlaşılmasın). */
let dummyHash: Promise<string> | null = null;
export async function burnPasswordTime(pw: string): Promise<void> {
  dummyHash ??= hashPassword("site-gozcu-sahte-sifre");
  await verifyPassword(pw, await dummyHash);
}

export function passwordProblem(pw: string, email: string): string | null {
  if (pw.length < PASSWORD_MIN) return `Şifre en az ${PASSWORD_MIN} karakter olmalı`;
  if (pw.length > PASSWORD_MAX) return `Şifre en fazla ${PASSWORD_MAX} karakter olabilir`;
  if (pw.toLowerCase().includes(email.split("@")[0].toLowerCase()) && email.split("@")[0].length >= 4) return "Şifre e-posta adınızı içermemeli";
  if (new Set(pw).size < 6) return "Şifre çok tekrarlı; daha çeşitli karakterler kullanın";
  return null;
}

// ——— Belirteçler ———

export const randomToken = (bytes = 32) => randomBytes(bytes).toString("base64url");
export const sha256 = (s: string) => createHash("sha256").update(s).digest("hex");

export function safeEqual(a: string, b: string): boolean {
  const x = Buffer.from(a);
  const y = Buffer.from(b);
  return x.length === y.length && timingSafeEqual(x, y);
}

// ——— TOTP (RFC 6238, SHA-1, 6 hane, 30 sn) ———

const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

export function base32Encode(buf: Buffer): string {
  let bits = 0;
  let value = 0;
  let out = "";
  for (const b of buf) {
    value = (value << 8) | b;
    bits += 8;
    while (bits >= 5) {
      out += B32[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += B32[(value << (5 - bits)) & 31];
  return out;
}

export function base32Decode(s: string): Buffer {
  const clean = s.toUpperCase().replace(/[^A-Z2-7]/g, "");
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const ch of clean) {
    value = (value << 5) | B32.indexOf(ch);
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

export const newTotpSecret = () => base32Encode(randomBytes(20));

export function totpAt(secretB32: string, step: number, digits = 6): string {
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(step));
  const h = createHmac("sha1", base32Decode(secretB32)).update(counter).digest();
  const off = h[h.length - 1] & 15;
  const bin = ((h[off] & 0x7f) << 24) | (h[off + 1] << 16) | (h[off + 2] << 8) | h[off + 3];
  return String(bin % 10 ** digits).padStart(digits, "0");
}

/**
 * Kodu doğrular; saat kayması için ±1 adım tolerans. Başarılıysa kullanılan adımı döner.
 * lastStep: bu kullanıcının en son kabul edilen adımı — aynı ya da daha eski adım tekrar kabul edilmez.
 */
export function verifyTotp(secretB32: string, code: string, lastStep: number, now = Date.now()): number | null {
  const c = code.replace(/\s/g, "");
  if (!/^\d{6}$/.test(c)) return null;
  const step = Math.floor(now / 30_000);
  for (const s of [step, step - 1, step + 1]) {
    if (s > lastStep && safeEqual(totpAt(secretB32, s), c)) return s;
  }
  return null;
}

export function otpauthUrl(secretB32: string, account: string, issuer = "Site Gözcü"): string {
  const label = encodeURIComponent(`${issuer}:${account}`);
  return `otpauth://totp/${label}?secret=${secretB32}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=30`;
}

// ——— Kurtarma kodları ———

export function newRecoveryCodes(n = 8): string[] {
  return Array.from({ length: n }, () => {
    const s = base32Encode(randomBytes(7)).slice(0, 10).toLowerCase();
    return `${s.slice(0, 5)}-${s.slice(5)}`;
  });
}

export const normalizeRecovery = (s: string) => s.toLowerCase().replace(/[^a-z2-7]/g, "");

// ——— 2FA sırrını veritabanında şifreli tutma (AES-256-GCM) ———

/** Her kullanım alanı (2FA sırrı, API imza anahtarı) APP_SECRET'tan ayrı bir şifreleme anahtarı türetir. */
const keyFrom = (appSecret: string, context: string) => createHash("sha256").update(`site-gozcu:${context}:` + appSecret).digest();

export function encryptSecret(plain: string, appSecret: string, context = "totp"): string {
  const iv = randomBytes(12);
  const c = createCipheriv("aes-256-gcm", keyFrom(appSecret, context), iv);
  const enc = Buffer.concat([c.update(plain, "utf8"), c.final()]);
  return `v1.${iv.toString("base64")}.${c.getAuthTag().toString("base64")}.${enc.toString("base64")}`;
}

export function decryptSecret(stored: string, appSecret: string, context = "totp"): string {
  const [v, iv, tag, data] = stored.split(".");
  if (v !== "v1") throw new Error("bilinmeyen şifreleme sürümü");
  const d = createDecipheriv("aes-256-gcm", keyFrom(appSecret, context), Buffer.from(iv, "base64"));
  d.setAuthTag(Buffer.from(tag, "base64"));
  return Buffer.concat([d.update(Buffer.from(data, "base64")), d.final()]).toString("utf8");
}
