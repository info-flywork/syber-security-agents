import { describe, expect, it } from "vitest";
import {
  checkSensitive,
  dnsChanges,
  externalHosts,
  fetchDns,
  fetchPage,
  headerResults,
  httpsResult,
  redirectResult,
  sameSite,
  scriptResult,
  uptimeResult,
} from "../src/checks";
import { COMMON_SENSITIVE_PATHS, EXECUTABLE_RE } from "../src/defaults";
import type { FetchFn } from "../src/types";

const O = "https://ornek.com";

function fake(routes: Record<string, (init?: RequestInit) => Response | Promise<Response>>) {
  const calls: { url: string; method: string }[] = [];
  const fn = (async (url: string, init?: RequestInit) => {
    calls.push({ url, method: init?.method ?? "GET" });
    const h = routes[url];
    return h ? h(init) : new Response("<html>404</html>", { status: 404, headers: { "content-type": "text/html" } });
  }) as FetchFn;
  return Object.assign(fn, { calls });
}

describe("erişim ve yönlendirme", () => {
  it("200'ü sağlıklı sayar, HTML ve başlıkları saklar", async () => {
    const p = await fetchPage(fake({ [`${O}/`]: () => new Response("<p>x</p>", { headers: { "content-type": "text/html", Server: "nginx" } }) }), O, "/");
    expect(uptimeResult(p).ok).toBe(true);
    expect(p.html).toBe("<p>x</p>");
    expect(p.headers.server).toBe("nginx");
  });

  it("5xx ve bağlantı hatasını sorun sayar", async () => {
    const f = fake({ [`${O}/`]: () => new Response("", { status: 502 }), [`${O}/a`]: () => Promise.reject(new TypeError("refused")) });
    expect(uptimeResult(await fetchPage(f, O, "/")).ok).toBe(false);
    const b = uptimeResult(await fetchPage(f, O, "/a"));
    expect(b.ok).toBe(false);
    expect(b.detail).toContain("refused");
  });

  it("Cloudflare/WAF doğrulama sayfasını kapalı saymaz", async () => {
    const p = await fetchPage(fake({ [`${O}/`]: () => new Response("", { status: 403, headers: { "cf-mitigated": "challenge" } }) }), O, "/");
    expect(uptimeResult(p).ok).toBe(true);
  });

  it("başka alan adına yönlendirmeyi yakalar, kendi alanına izin verir", async () => {
    const f = fake({
      [`${O}/`]: () => new Response(null, { status: 302, headers: { location: "https://kotu.example/x" } }),
      [`${O}/a`]: () => new Response(null, { status: 301, headers: { location: "https://www.ornek.com/a" } }),
    });
    expect(redirectResult(await fetchPage(f, O, "/"), O).ok).toBe(false);
    expect(redirectResult(await fetchPage(f, O, "/a"), O).ok).toBe(true);
  });

  it("alan adı karşılaştırması", () => {
    expect(sameSite("www.ornek.com", "ornek.com")).toBe(true);
    expect(sameSite("cdn.ornek.com", "ornek.com")).toBe(true);
    expect(sameSite("ornek.com.kotu.example", "ornek.com")).toBe(false);
    expect(sameSite("benornek.com", "ornek.com")).toBe(false);
  });
});

describe("HTTPS", () => {
  it("http → https yönlendirmesini doğrular", async () => {
    const ok = await httpsResult(fake({ "http://ornek.com/": () => new Response(null, { status: 301, headers: { location: "https://ornek.com/" } }) }), O);
    expect(ok.ok).toBe(true);
    const bad = await httpsResult(fake({ "http://ornek.com/": () => new Response("site", { status: 200 }) }), O);
    expect(bad.ok).toBe(false);
  });

  it("http:// siteyi şifresiz olarak işaretler", async () => {
    expect((await httpsResult(fake({}), "http://ornek.com")).ok).toBe(false);
  });

  it("80 portu kapalıysa sorun saymaz", async () => {
    expect((await httpsResult(fake({ "http://ornek.com/": () => Promise.reject(new TypeError("refused")) }), O)).ok).toBe(true);
  });
});

describe("güvenlik başlıkları", () => {
  it("eksikleri bilgi olarak işaretler, sürüm sızıntısını yakalar", async () => {
    const p = await fetchPage(fake({ [`${O}/`]: () => new Response("x", { headers: { "content-type": "text/html", server: "Apache/2.4.41 (Ubuntu)", "x-powered-by": "PHP/7.4.3" } }) }), O, "/");
    const r = headerResults(p, O);
    expect(r.every((x) => x.severity === "info")).toBe(true);
    expect(r.find((x) => x.id === "headers:hsts")!.ok).toBe(false);
    expect(r.find((x) => x.id === "headers:version")!.detail).toContain("PHP/7.4.3");
  });

  it("tam başlıklı siteyi temiz sayar", async () => {
    const p = await fetchPage(
      fake({
        [`${O}/`]: () =>
          new Response("x", {
            headers: { "content-type": "text/html", "strict-transport-security": "max-age=31536000", "x-content-type-options": "nosniff", "content-security-policy": "frame-ancestors 'none'", server: "cloudflare" },
          }),
      }),
      O,
      "/",
    );
    expect(headerResults(p, O).every((x) => x.ok)).toBe(true);
  });
});

describe("dış kod", () => {
  const html = `<script src="https://cdn.jsdelivr.net/x.js"></script><script src="/yerel.js"></script>
<script src='//widget.getchaty.com/e.js' async></script><iframe src="https://kotu.example/f"></iframe>
<meta http-equiv="refresh" content="0; url=https://yonlen.example/"><img src="https://resim.example/a.png"><script src="https://www.ornek.com/b.js"></script>`;
  it("script/iframe/meta-refresh host'larını çıkarır, kendi alanını ve resimleri saymaz", () => {
    expect(externalHosts(html, `${O}/`)).toEqual(["cdn.jsdelivr.net", "kotu.example", "widget.getchaty.com", "yonlen.example"]);
  });
  it("bilinenleri kabul eder, yeniyi yakalar", () => {
    expect(scriptResult("/", ["a.example"], [], ["a.example"]).ok).toBe(true);
    const r = scriptResult("/", ["a.example", "yeni.example"], [], ["a.example"]);
    expect(r.ok).toBe(false);
    expect(r.detail).toContain("yeni.example");
  });
});

describe("hassas dosyalar", () => {
  it("indirilebilen dosyayı yakalar (HEAD ile)", async () => {
    const f = fake({ [`${O}/.env`]: () => new Response(null, { status: 200, headers: { "content-type": "text/plain", "content-length": "220" } }) });
    const r = await checkSensitive(f, O, "/.env");
    expect(r.ok).toBe(false);
    expect(r.detail).toContain("220");
    expect(f.calls[0].method).toBe("HEAD");
  });
  it("404/403 ve HTML 200'ü (soft-404) güvenli sayar", async () => {
    const f = fake({ [`${O}/a.zip`]: () => new Response(null, { status: 403 }), [`${O}/b.sql`]: () => new Response("<html>bulunamadı</html>", { headers: { "content-type": "text/html" } }) });
    expect((await checkSensitive(f, O, "/a.zip")).ok).toBe(true);
    expect((await checkSensitive(f, O, "/b.sql")).ok).toBe(true);
    expect((await checkSensitive(f, O, "/yok")).ok).toBe(true);
  });
  it("HEAD desteklenmezse 1 baytlık GET dener", async () => {
    const f = fake({
      [`${O}/db.sql`]: (i) => (i?.method === "HEAD" ? new Response(null, { status: 405 }) : new Response("C", { status: 206, headers: { "content-type": "application/sql" } })),
    });
    expect((await checkSensitive(f, O, "/db.sql")).ok).toBe(false);
    expect(f.calls.map((c) => c.method)).toEqual(["HEAD", "GET"]);
  });
  it("varsayılan listede çalıştırılabilir dosya yok", () => {
    for (const p of COMMON_SENSITIVE_PATHS) expect(EXECUTABLE_RE.test(p), p).toBe(false);
  });
});

describe("DNS", () => {
  it("DoH cevabını normalize eder ve değişikliği yakalar", async () => {
    const f = fake({
      "https://cloudflare-dns.com/dns-query?name=ornek.com&type=NS": () => Response.json({ Answer: [{ type: 2, data: "NS2.Host.com." }, { type: 2, data: "ns1.host.com." }] }),
    });
    const a = await fetchDns(f, "ornek.com", ["NS"]);
    expect(a).toEqual({ NS: ["ns1.host.com", "ns2.host.com"] });
    expect(dnsChanges(null, a)).toEqual([]);
    expect(dnsChanges(a, { NS: ["x.ns.cloudflare.com"] })[0].type).toBe("NS");
  });
});

describe("istek bütçesi", async () => {
  const { budgeted, sensitiveList } = await import("../src/plan");
  it("sınırdan sonra istek atmaz", async () => {
    let real = 0;
    const f = budgeted(async () => (real++, new Response("")), 3);
    for (let i = 0; i < 5; i++) await f("u").catch(() => undefined);
    expect(real).toBe(3);
    expect(f.used()).toBe(5);
  });
  it("siteye özel yollar önce, toplam sınır içinde", () => {
    const l = sensitiveList({ extraPaths: ["/ozel.zip"], pages: ["/", "/a", "/b"] } as never);
    expect(l[0]).toBe("/ozel.zip");
    expect(l.length).toBeLessThanOrEqual(37);
  });
});

describe("hassas dosya ağ hatası", () => {
  it("hata durumunda skip işaretler", async () => {
    const r = await checkSensitive(fake({ [`${O}/.env`]: () => Promise.reject(new TypeError("connection reset")) }), O, "/.env");
    expect(r.skip).toBe(true);
  });
});
