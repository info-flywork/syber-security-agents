/**
 * Panelden gelen site formunu doğrular. İç ağ adreslerine (SSRF) izin vermez.
 */
import { EXECUTABLE_RE, MAX_EXTRA_PATHS, MAX_PAGES } from "./defaults";
import type { SiteConfig } from "./types";

export interface SiteInput {
  url: string;
  name?: string;
  emails?: string;
  pages?: string;
  extraPaths?: string;
  intervalMin?: string | number;
  ownerConfirmed?: string | boolean;
}

export type Parsed = { ok: true; site: SiteConfig } | { ok: false; error: string };

const PRIVATE_HOST = /^(localhost|.*\.localhost|.*\.local|.*\.internal|.*\.lan|.*\.home|.*\.corp)$/i;

function isIpLiteral(h: string): boolean {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(h) || h.includes(":") || h.startsWith("[");
}

export function siteId(host: string): string {
  return host.replace(/^www\./, "").replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 60);
}

function lines(s: string | undefined): string[] {
  return (s ?? "").split(/[\n,]+/).map((x) => x.trim()).filter(Boolean);
}

function cleanPath(p: string): string | null {
  if (!p.startsWith("/")) p = "/" + p;
  if (p.length > 200 || /[\s<>"'\\]/.test(p) || p.includes("..")) return null;
  return p;
}

export function parseSiteInput(input: SiteInput, opts: { allowPrivate?: boolean; now?: string } = {}): Parsed {
  const raw = (input.url ?? "").trim();
  if (!raw) return { ok: false, error: "Site adresi gerekli" };
  let u: URL;
  try {
    u = new URL(/^https?:\/\//i.test(raw) ? raw : "https://" + raw);
  } catch {
    return { ok: false, error: "Geçersiz adres" };
  }
  if (u.protocol !== "https:" && u.protocol !== "http:") return { ok: false, error: "Sadece http/https" };
  if (u.username || u.password) return { ok: false, error: "Adreste kullanıcı adı / şifre olamaz" };
  const host = u.hostname.toLowerCase();
  if (!opts.allowPrivate) {
    if (isIpLiteral(host)) return { ok: false, error: "IP adresi yerine alan adı girin" };
    if (PRIVATE_HOST.test(host) || !host.includes(".")) return { ok: false, error: "İç ağ adresleri izlenemez" };
  }
  if (!(input.ownerConfirmed === true || input.ownerConfirmed === "on" || input.ownerConfirmed === "1")) {
    return { ok: false, error: "Bu siteyi izleme yetkiniz olduğunu onaylamalısınız" };
  }

  const emails = lines(input.emails).map((e) => e.toLowerCase());
  const badMail = emails.find((e) => !/^[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+$/.test(e));
  if (badMail) return { ok: false, error: `Geçersiz e-posta: ${badMail}` };
  if (emails.length > 10) return { ok: false, error: "En fazla 10 e-posta" };

  const pages = ["/", ...lines(input.pages)].map(cleanPath);
  if (pages.includes(null)) return { ok: false, error: "Geçersiz sayfa yolu" };
  const uniqPages = [...new Set(pages as string[])].slice(0, MAX_PAGES);

  const extra = lines(input.extraPaths).map(cleanPath);
  if (extra.includes(null)) return { ok: false, error: "Geçersiz dosya yolu" };
  const exec = (extra as string[]).find((p) => EXECUTABLE_RE.test(p));
  if (exec) return { ok: false, error: `${exec}: çalıştırılabilir dosyalar denenmez (istek atmak onu çalıştırır)` };
  if (extra.length > MAX_EXTRA_PATHS) return { ok: false, error: `En fazla ${MAX_EXTRA_PATHS} ek dosya yolu` };

  const iv = Number(input.intervalMin ?? 15);
  const intervalMin = (iv === 5 || iv === 15 || iv === 60 ? iv : 15) as 5 | 15 | 60;
  const origin = `${u.protocol}//${u.host}`.toLowerCase();
  return {
    ok: true,
    site: {
      id: siteId(host),
      name: (input.name ?? "").trim().slice(0, 80) || host,
      origin,
      pages: uniqPages,
      extraPaths: [...new Set(extra as string[])],
      emails,
      intervalMin,
      paused: false,
      createdAt: opts.now ?? new Date().toISOString(),
      ownerConfirmed: true,
    },
  };
}
