/**
 * Kontroller — saf fonksiyonlar; fetch dışarıdan verilir (testte sahte fetch).
 */
import { REQUEST_TIMEOUT_MS, SLOW_MS, USER_AGENT } from "./defaults";
import type { CheckResult, FetchFn } from "./types";

export interface PageFetch {
  path: string;
  status: number;
  ms: number;
  location: string | null;
  headers: Record<string, string>;
  html: string | null;
  error: string | null;
}

function reqInit(init: RequestInit = {}): RequestInit {
  return {
    ...init,
    redirect: "manual",
    signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    headers: { "User-Agent": USER_AGENT, ...(init.headers as Record<string, string> | undefined) },
  };
}

function headerMap(h: Headers): Record<string, string> {
  const out: Record<string, string> = {};
  h.forEach((v, k) => (out[k.toLowerCase()] = v));
  return out;
}

export async function fetchPage(fetchFn: FetchFn, origin: string, path: string): Promise<PageFetch> {
  const started = Date.now();
  try {
    const res = await fetchFn(origin + path, reqInit());
    const headers = headerMap(res.headers);
    const ct = headers["content-type"] ?? "";
    const html = ct.includes("text/html") && res.status < 300 ? (await res.text()).slice(0, 2_000_000) : null;
    if (html === null) await res.body?.cancel();
    return { path, status: res.status, ms: Date.now() - started, location: headers["location"] ?? null, headers, html, error: null };
  } catch (e) {
    return { path, status: 0, ms: Date.now() - started, location: null, headers: {}, html: null, error: errMsg(e) };
  }
}

export function uptimeResult(p: PageFetch): CheckResult {
  // Cloudflare / WAF doğrulama sayfası siteyi kapalı göstermez
  const challenged = "cf-mitigated" in p.headers;
  const ok = p.error === null && ((p.status >= 200 && p.status < 400) || challenged);
  const detail = p.error
    ? `Bağlanılamadı: ${p.error}`
    : `HTTP ${p.status} · ${p.ms} ms${p.ms > SLOW_MS ? " · yavaş" : ""}${challenged ? " · bot doğrulaması" : ""}`;
  return { id: `up:${p.path}`, kind: "uptime", title: `${p.path} erişilemiyor`, ok, severity: "critical", detail };
}

export function redirectResult(p: PageFetch, origin: string): CheckResult {
  let ok = true;
  let detail = "Yönlendirme yok ya da kendi alan adına";
  if (p.status >= 300 && p.status < 400 && p.location) {
    let target = "";
    try {
      target = new URL(p.location, origin + p.path).hostname.toLowerCase();
    } catch {
      /* geçersiz Location */
    }
    if (target && !sameSite(target, hostOf(origin))) {
      ok = false;
      detail = `${p.path} → ${p.location} adresine yönlendiriyor`;
    }
  }
  return { id: `redirect:${p.path}`, kind: "redirect", title: `${p.path} başka siteye yönlendiriyor`, ok, severity: "critical", detail };
}

/** http:// adresi https://'e yönlendiriyor mu? */
export async function httpsResult(fetchFn: FetchFn, origin: string): Promise<CheckResult> {
  const base = { id: "https:redirect", kind: "https" as const, title: "HTTP bağlantısı HTTPS'e yönlendirilmiyor", severity: "high" as const };
  if (!origin.startsWith("https://")) {
    return { ...base, ok: false, detail: "Site HTTPS kullanmıyor; bağlantılar şifresiz" };
  }
  try {
    const res = await fetchFn("http://" + origin.slice(8) + "/", reqInit());
    await res.body?.cancel();
    const loc = res.headers.get("location") ?? "";
    const ok = res.status >= 300 && res.status < 400 && loc.toLowerCase().startsWith("https://");
    return { ...base, ok, detail: ok ? `HTTP ${res.status} → HTTPS` : `http:// adresi HTTP ${res.status} döndü, HTTPS'e yönlendirmedi` };
  } catch (e) {
    // 80 portu kapalıysa şifresiz erişim zaten yoktur
    return { ...base, ok: true, detail: `http:// erişilemiyor (${errMsg(e)})` };
  }
}

/** Güvenlik başlıkları — bilgi amaçlı (e-posta gönderilmez, panelde görünür). */
export function headerResults(p: PageFetch, origin: string): CheckResult[] {
  const h = p.headers;
  if (p.error || p.status === 0) return [];
  const csp = h["content-security-policy"] ?? "";
  const mk = (key: string, title: string, ok: boolean, detail: string): CheckResult => ({ id: `headers:${key}`, kind: "headers", title, ok, severity: "info", detail });
  const out: CheckResult[] = [];
  if (origin.startsWith("https://")) {
    out.push(mk("hsts", "HSTS başlığı yok", !!h["strict-transport-security"], h["strict-transport-security"] ? "Strict-Transport-Security var" : "Tarayıcılar ilk bağlantıda HTTP'ye düşebilir"));
  }
  out.push(mk("nosniff", "X-Content-Type-Options başlığı yok", (h["x-content-type-options"] ?? "").toLowerCase() === "nosniff", h["x-content-type-options"] ? `X-Content-Type-Options: ${h["x-content-type-options"]}` : "Eksik"));
  const framing = !!h["x-frame-options"] || /frame-ancestors/i.test(csp);
  out.push(mk("framing", "Sayfa başka sitelere gömülebilir (clickjacking)", framing, framing ? "X-Frame-Options / frame-ancestors var" : "X-Frame-Options ya da CSP frame-ancestors yok"));
  const leak = [h["server"], h["x-powered-by"]].filter((v): v is string => !!v && /\d/.test(v));
  out.push(mk("version", "Sunucu yazılım sürümü açıkta", leak.length === 0, leak.length ? `Görünen: ${leak.join(", ")}` : "Sürüm bilgisi gizli"));
  return out;
}

/** HTML içindeki dış kaynak host'ları: script src, iframe src, meta refresh. */
export function externalHosts(html: string, pageUrl: string): string[] {
  const own = hostOf(pageUrl);
  const hosts = new Set<string>();
  const add = (raw: string) => {
    const v = raw.trim();
    if (!v || /^(data:|javascript:|#|about:)/i.test(v)) return;
    try {
      const h = new URL(v, pageUrl).hostname.toLowerCase();
      if (h && !sameSite(h, own)) hosts.add(h);
    } catch {
      /* geçersiz URL */
    }
  };
  for (const m of html.matchAll(/<script\b[^>]*?\bsrc\s*=\s*["']?([^"'\s>]+)/gi)) add(m[1]);
  for (const m of html.matchAll(/<iframe\b[^>]*?\bsrc\s*=\s*["']?([^"'\s>]+)/gi)) add(m[1]);
  for (const m of html.matchAll(/<meta\b[^>]*http-equiv\s*=\s*["']?refresh[^>]*content\s*=\s*["'][^"']*url\s*=\s*([^"'>\s]+)/gi)) add(m[1]);
  return [...hosts].sort();
}

export function scriptResult(path: string, hosts: string[], allowed: string[], baseline: string[] | undefined): CheckResult {
  const known = new Set([...allowed, ...(baseline ?? [])].map((h) => h.toLowerCase()));
  const unknown = hosts.filter((h) => !known.has(h));
  return {
    id: `script:${path}`,
    kind: "script",
    title: `${path} sayfasında tanınmayan dış kod`,
    ok: unknown.length === 0,
    severity: "high",
    detail: unknown.length ? `Yeni dış kaynak: ${unknown.join(", ")}` : `${hosts.length} dış kaynak, hepsi biliniyor`,
  };
}

/**
 * Hassas dosya dışarıdan indirilebiliyor mu?
 * 200/206 + HTML olmayan içerik = açık. (HTML dönen 200 genelde sitenin kendi "bulunamadı" sayfasıdır.)
 */
export async function checkSensitive(fetchFn: FetchFn, origin: string, path: string): Promise<CheckResult> {
  const id = `exposed:${path}`;
  const title = `${path} dışarıdan indirilebiliyor`;
  try {
    const url = origin + encodeURI(path);
    let res = await fetchFn(url, reqInit({ method: "HEAD" }));
    if (res.status === 405 || res.status === 501) {
      await res.body?.cancel();
      res = await fetchFn(url, reqInit({ method: "GET", headers: { Range: "bytes=0-0" } }));
    }
    await res.body?.cancel();
    const ct = res.headers.get("content-type") ?? "";
    const exposed = (res.status === 200 || res.status === 206) && !ct.includes("text/html");
    const len = res.headers.get("content-length");
    return {
      id,
      kind: "exposed",
      title,
      ok: !exposed,
      severity: "critical",
      detail: exposed ? `HTTP ${res.status} · ${ct || "tür yok"}${len ? ` · ${len} bayt` : ""}` : `HTTP ${res.status}`,
    };
  } catch (e) {
    // Geçici hata "düzeldi" sayılmaz: önceki durum korunur
    return { id, kind: "exposed", title, ok: true, skip: true, severity: "critical", detail: `Kontrol edilemedi: ${errMsg(e)}` };
  }
}

const RR_CODES: Record<string, number> = { A: 1, NS: 2, CNAME: 5, MX: 15, TXT: 16, AAAA: 28 };

export async function fetchDns(fetchFn: FetchFn, name: string, types: string[]): Promise<Record<string, string[]>> {
  const out: Record<string, string[]> = {};
  for (const t of types) {
    const res = await fetchFn(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=${t}`, {
      headers: { accept: "application/dns-json" },
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });
    if (!res.ok) throw new Error(`DoH ${t}: HTTP ${res.status}`);
    const json = (await res.json()) as { Answer?: { type: number; data: string }[] };
    out[t] = (json.Answer ?? [])
      .filter((a) => a.type === RR_CODES[t])
      .map((a) => a.data.toLowerCase().replace(/\.$/, ""))
      .sort();
  }
  return out;
}

export function dnsChanges(prev: Record<string, string[]> | null, next: Record<string, string[]>) {
  if (!prev) return [];
  const out: { type: string; before: string[]; after: string[] }[] = [];
  for (const t of Object.keys(next)) {
    if (prev[t] !== undefined && prev[t].join("|") !== next[t].join("|")) out.push({ type: t, before: prev[t], after: next[t] });
  }
  return out;
}

export function hostOf(url: string): string {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    return "";
  }
}

/** www ve alt alan adları aynı site sayılır. */
export function sameSite(a: string, b: string): boolean {
  const x = a.replace(/^www\./, "");
  const y = b.replace(/^www\./, "");
  return x === y || x.endsWith("." + y) || y.endsWith("." + x);
}

export function errMsg(e: unknown): string {
  if (e instanceof Error) return e.name === "TimeoutError" ? "zaman aşımı" : e.message;
  return String(e);
}
