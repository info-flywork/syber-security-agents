import { describe, expect, it } from "vitest";
import { evaluate, mailworthy } from "../src/incidents";
import { buildAlert } from "../src/alert";
import { parseSiteInput } from "../src/site-input";
import { RateLimiter, readCookie, safeNext, sameOrigin, sessionCookie } from "../src/auth";
import { dashboard, siteDetail, siteHealth, uptimePct } from "../src/ui";
import type { CheckResult, SiteConfig, SiteState } from "../src/types";

const down = (ok: boolean): CheckResult => ({ id: "up:/", kind: "uptime", title: "/ erişilemiyor", ok, severity: "critical", detail: ok ? "200" : "zaman aşımı" });
const env = (ok: boolean): CheckResult => ({ id: "exposed:/.env", kind: "exposed", title: "/.env dışarıdan indirilebiliyor", ok, severity: "critical", detail: ok ? "404" : "200" });
const hsts = (ok: boolean): CheckResult => ({ id: "headers:hsts", kind: "headers", title: "HSTS başlığı yok", ok, severity: "info", detail: "" });

describe("olay takibi", () => {
  it("kesinti 2. hatada uyarır, sonra susar, düzelince bildirir", () => {
    let s = evaluate({}, [down(false)], "2026-10-16T10:00:00Z");
    expect(s.opened).toHaveLength(0);
    s = evaluate(s.incidents, [down(false)], "2026-10-16T10:05:00Z");
    expect(s.opened).toHaveLength(1);
    s = evaluate(s.incidents, [down(false)], "2026-10-16T10:10:00Z");
    expect(s.opened).toHaveLength(0);
    s = evaluate(s.incidents, [down(true)], "2026-10-16T10:15:00Z");
    expect(s.resolved).toHaveLength(1);
    expect(s.incidents).toEqual({});
  });
  it("tek seferlik hata sessiz geçer; açık dosya hemen uyarır", () => {
    let s = evaluate({}, [down(false)], "t1");
    s = evaluate(s.incidents, [down(true)], "t2");
    expect(s.opened.length + s.resolved.length).toBe(0);
    expect(evaluate({}, [env(false)], "t1").opened).toHaveLength(1);
  });
  it("bilgi seviyesi (başlık) olaylar e-posta listesine girmez", () => {
    const s = evaluate({}, [env(false), hsts(false)], "t1");
    expect(s.opened).toHaveLength(2);
    expect(mailworthy(s.opened).map((i) => i.id)).toEqual(["exposed:/.env"]);
  });
});

const site = (over: Partial<SiteConfig> = {}): SiteConfig => ({
  id: "ornek-com", name: "Örnek <Şirket>", origin: "https://ornek.com", pages: ["/"], extraPaths: [], emails: ["a@ornek.com"],
  intervalMin: 15, paused: false, createdAt: "2026-10-16T10:00:00Z", ownerConfirmed: true, ...over,
});

describe("site formu", () => {
  it("adresi normalize eder, varsayılanları uygular", () => {
    const r = parseSiteInput({ url: "Ornek.com/hakkimizda?x=1", emails: "A@ornek.com, b@ornek.com", pages: "/giris\n/giris", ownerConfirmed: "1" }, { now: "n" });
    expect(r.ok && r.site).toMatchObject({ id: "ornek-com", origin: "https://ornek.com", emails: ["a@ornek.com", "b@ornek.com"], pages: ["/", "/giris"], intervalMin: 15 });
  });
  it("izin onayı olmadan eklemez", () => {
    expect(parseSiteInput({ url: "ornek.com" })).toMatchObject({ ok: false });
  });
  it("iç ağ ve IP adreslerini reddeder", () => {
    for (const url of ["http://localhost:8080", "http://192.168.1.1", "https://10.0.0.5", "http://[::1]/", "https://intranet", "https://printer.local", "https://db.internal"]) {
      expect(parseSiteInput({ url, ownerConfirmed: "1" }).ok, url).toBe(false);
    }
    expect(parseSiteInput({ url: "http://localhost:8080", ownerConfirmed: "1" }, { allowPrivate: true }).ok).toBe(true);
  });
  it("çalıştırılabilir ek yolu, kötü yolu ve kötü e-postayı reddeder", () => {
    expect(parseSiteInput({ url: "ornek.com", extraPaths: "/admin/setup.php", ownerConfirmed: "1" })).toMatchObject({ ok: false });
    expect(parseSiteInput({ url: "ornek.com", extraPaths: "/../etc/passwd", ownerConfirmed: "1" })).toMatchObject({ ok: false });
    expect(parseSiteInput({ url: "ornek.com", emails: "a@b", ownerConfirmed: "1" })).toMatchObject({ ok: false });
    expect(parseSiteInput({ url: "https://user:pw@ornek.com", ownerConfirmed: "1" })).toMatchObject({ ok: false });
  });
});

describe("oturum", () => {
  it("çerezden oturum belirtecini okur", () => {
    expect(readCookie("a=1; sg_session=abc", "sg_session")).toBe("abc");
    expect(readCookie("sg_session=", "sg_session")).toBe(null);
    expect(readCookie(null, "sg_session")).toBe(null);
    expect(sessionCookie("t", true)).toContain("Secure");
    expect(sessionCookie("t", true)).toContain("HttpOnly");
    expect(sessionCookie("", false, true)).toContain("Max-Age=0");
  });
  it("başka kaynaktan gelen POST'u reddeder (CSRF)", () => {
    const O = "https://gozcu.example";
    const mk = (h: Record<string, string>) => new Request(`${O}/sites`, { method: "POST", headers: h });
    expect(sameOrigin(mk({ origin: O }), O)).toBe(true);
    expect(sameOrigin(mk({ origin: "https://kotu.example" }), O)).toBe(false);
    expect(sameOrigin(mk({}), O)).toBe(false);
    expect(sameOrigin(mk({ "sec-fetch-site": "same-origin" }), O)).toBe(true);
    expect(sameOrigin(mk({ origin: "null", "sec-fetch-site": "same-origin" }), O)).toBe(true);
    expect(sameOrigin(mk({ origin: "null", "sec-fetch-site": "cross-site" }), O)).toBe(false);
    expect(sameOrigin(mk({ origin: "null" }), O)).toBe(false);
  });
  it("giriş sonrası sadece panel içi yollara yönlendirir", () => {
    expect(safeNext("/davet/abc_DEF-123")).toBe("/davet/abc_DEF-123");
    for (const bad of ["//kotu.example", "https://kotu.example", "/x?y=1", "javascript:alert(1)", null]) expect(safeNext(bad)).toBe("/");
  });
  it("hız sınırı pencere içinde fazlasını reddeder", () => {
    const rl = new RateLimiter(2, 1000);
    expect([rl.allow("k", 0), rl.allow("k", 1), rl.allow("k", 2), rl.allow("k", 1001)]).toEqual([true, true, false, true]);
  });
});

const state = (over: Partial<SiteState> = {}): SiteState => ({
  incidents: {}, dnsBaseline: null, scriptBaseline: {}, lastRun: "2026-10-16T10:00:00Z", lastDurationMs: 500, lastResults: [],
  lastMail: null, history: [], events: [], runs: 1, ...over,
});

describe("panel", () => {
  it("durumu doğru hesaplar", () => {
    expect(siteHealth(site(), null)).toBe("unknown");
    expect(siteHealth(site({ paused: true }), state())).toBe("paused");
    expect(siteHealth(site(), state())).toBe("ok");
    const e = evaluate({}, [env(false)], "t").incidents;
    expect(siteHealth(site(), state({ incidents: e }))).toBe("issues");
    const info = evaluate({}, [hsts(false)], "t").incidents;
    expect(siteHealth(site(), state({ incidents: info }))).toBe("ok");
    expect(uptimePct(state({ history: [{ at: "", up: true, failing: 0, ms: 1 }, { at: "", up: false, failing: 1, ms: 1 }] }))).toBe("%50");
  });
  it("kullanıcı verisini HTML'de kaçırır", () => {
    const evil = site({ name: '<script>alert(1)</script>', emails: ['"><img src=x onerror=alert(1)>@x.com'] });
    const st = state({ events: [{ at: "2026-10-16T10:00:00Z", type: "opened", kind: "script", title: "<b>x</b>", detail: "<iframe>", severity: "high" }] });
    for (const out of [dashboard([{ site: evil, st }], "<svg onload=1>", true), siteDetail(evil, st, null, false)]) {
      expect(out).not.toContain("<script>alert");
      expect(out).not.toContain("<img src=x");
      expect(out).not.toContain("<iframe>");
      expect(out).not.toContain("<svg onload");
    }
  });
});

describe("uyarı e-postası", () => {
  it("site adı, öneri ve kaçış", () => {
    const s = evaluate({}, [env(false)], "2026-10-16T10:00:00Z");
    const a = buildAlert(site(), s.opened, [], [], "2026-10-16T10:00:00Z", "https://p/site/ornek-com");
    expect(a.subject).toBe("🔴 Örnek <Şirket>: /.env dışarıdan indirilebiliyor");
    expect(a.html).toContain("Örnek &lt;Şirket&gt;");
    expect(a.html).toContain("Sunucudan silin");
    expect(a.html).toContain("https://p/site/ornek-com");
    expect(buildAlert(site(), [], [], [], "2026-10-16T10:00:00Z", "", true).subject.startsWith("✅")).toBe(true);
  });
});

describe("geçici hata", () => {
  it("kontrol edilemeyen dosya açık olayı kapatmaz, yeni olay da açmaz", () => {
    let s = evaluate({}, [env(false)], "t1");
    s = evaluate(s.incidents, [{ ...env(true), skip: true, detail: "Kontrol edilemedi: reset" }], "t2");
    expect(s.resolved).toHaveLength(0);
    expect(Object.keys(s.incidents)).toEqual(["exposed:/.env"]);
    s = evaluate(s.incidents, [env(true)], "t3");
    expect(s.resolved).toHaveLength(1);
  });
});
