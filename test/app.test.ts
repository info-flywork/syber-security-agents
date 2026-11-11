/**
 * Uçtan uca: gerçek PostgreSQL'e karşı panel akışları. TEST_DATABASE_URL yoksa atlanır.
 * Yerel: npm run db:dev && TEST_DATABASE_URL=postgres://sitegozcu:yerel-gelistirme@127.0.0.1:55432/sitegozcu_test npm test
 * DİKKAT: Test veritabanı her çalıştırmada sıfırlanır.
 */
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { changeMember, createInvite, createOrg } from "../src/accounts";
import { signRequest } from "../src/apikeys";
import { createApp } from "../src/app";
import type { Config } from "../src/config";
import { createPool, migrate, type Db } from "../src/db";
import { decryptSecret, totpAt } from "../src/security";

const DB_URL = process.env.TEST_DATABASE_URL;
const PUBLIC = "http://panel.test";
const cfg: Config = {
  databaseUrl: DB_URL ?? "",
  publicUrl: PUBLIC,
  port: 0,
  appSecret: "t".repeat(40),
  trustProxy: false,
  allowPrivate: false,
  cron: false,
  devNoAuth: false,
  devUser: null,
  smtp: { host: "", port: 465, secure: "tls", user: "", pass: "", from: "x@panel.test", fromName: "" },
};

/** Ağa çıkmayan sahte site: ana sayfa 200, diğer her şey 404, DNS boş. */
const fakeFetch = async (url: string) => {
  if (url.includes("dns-query")) return new Response(JSON.stringify({ Answer: [] }), { headers: { "content-type": "application/dns-json" } });
  if (new URL(url).pathname === "/") return new Response("<html><body>merhaba</body></html>", { status: 200, headers: { "content-type": "text/html" } });
  return new Response("yok", { status: 404 });
};

describe.skipIf(!DB_URL)("panel (PostgreSQL)", () => {
  let db: Db;
  let app: ReturnType<typeof createApp>;
  const mails: { to: string[]; subject: string; html: string }[] = [];
  let orgA = "";
  let orgB = "";

  /** Basit tarayıcı: çerez saklar, POST'larda Origin gönderir. */
  function browser(ip: string) {
    let cookie = "";
    const go = async (method: "GET" | "POST", path: string, form?: Record<string, string>, origin = PUBLIC) => {
      const headers: Record<string, string> = { cookie, "user-agent": "vitest" };
      if (method === "POST" && origin) headers.origin = origin;
      const res = await app(new Request(PUBLIC + path, { method, headers, body: form ? new URLSearchParams(form) : undefined }), { ip });
      const sc = res.headers.get("set-cookie");
      if (sc) cookie = sc.split(";")[0].endsWith("=") ? "" : sc.split(";")[0];
      return { status: res.status, location: res.headers.get("location"), text: await res.text() };
    };
    return { get: (p: string) => go("GET", p), post: (p: string, f: Record<string, string> = {}, origin?: string) => go("POST", p, f, origin) };
  }

  async function secretOf(email: string): Promise<string> {
    const { rows } = await db.query<{ totp_secret: string }>("SELECT totp_secret FROM users WHERE email = $1", [email]);
    return decryptSecret(rows[0].totp_secret, cfg.appSecret);
  }
  const code = (secret: string, offset = 0) => totpAt(secret, Math.floor(Date.now() / 30_000) + offset);
  /** Kullanıcının en son kabul edilen adımı ve ondan sonraki ilk geçerli adımın kodu (30 sn sınırından bağımsız). */
  async function steps(email: string, secret: string) {
    const { rows } = await db.query<{ s: string }>("SELECT totp_last_step::text AS s FROM users WHERE email = $1", [email]);
    const last = Number(rows[0].s);
    const now = Math.floor(Date.now() / 30_000);
    return { used: totpAt(secret, last), fresh: totpAt(secret, Math.max(now, last + 1)) };
  }

  /** Davetle kayıt + 2FA kurulumu; kurtarma kodlarını döner. */
  async function onboard(b: ReturnType<typeof browser>, token: string, email: string) {
    let r = await b.post(`/davet/${token}`, { password: "Mavi-Kedi-Kosar-77", password2: "Mavi-Kedi-Kosar-77" });
    expect(r.status).toBe(303);
    expect(r.location).toBe("/2fa/kurulum");
    r = await b.get("/2fa/kurulum"); // sır üretilir
    r = r.status === 303 ? await b.get("/2fa/kurulum") : r;
    expect(r.status).toBe(200);
    expect(r.text).toContain("<svg");
    const secret = await secretOf(email);
    r = await b.post("/2fa/kurulum", { code: code(secret) });
    expect(r.status).toBe(200);
    const codes = recoveryCodes(r.text);
    expect(codes).toHaveLength(8);
    return { secret, codes };
  }

  /** Kurtarma kodları sadece sayfadaki <pre> bloğunda */
  const recoveryCodes = (html: string) => (html.match(/<pre[^>]*>([^<]*)<\/pre>/)?.[1] ?? "").split("\n").filter(Boolean);

  const linkToken = (html: string) => html.match(/\/davet\/([A-Za-z0-9_-]+)/)![1];

  beforeAll(async () => {
    db = createPool(DB_URL!);
    await db.query("DROP SCHEMA public CASCADE; CREATE SCHEMA public;");
    await migrate(db);
    app = createApp({
      cfg,
      db,
      monitor: { db, fetchFn: fakeFetch, mailer: null, publicUrl: PUBLIC },
      mailer: async (to, subject, html) => void mails.push({ to, subject, html }),
    });
    orgA = await createOrg(db, "ARCON");
    orgB = await createOrg(db, "Başka Müşteri");
  });
  afterAll(async () => {
    await db?.end();
  });

  const alice = browser("10.0.0.1");
  const bob = browser("10.0.0.2");
  const carol = browser("10.0.0.3");
  let aliceSecret = "";
  let aliceCodes: string[] = [];

  it("sahip davetle hesap açar, 2FA kurmadan panele giremez", async () => {
    const { token } = await createInvite(db, orgA, "alice@arcon.test", "owner", null);
    const r0 = await alice.post(`/davet/${token}`, { password: "Mavi-Kedi-Kosar-77", password2: "Mavi-Kedi-Kosar-77" });
    expect(r0.location).toBe("/2fa/kurulum");
    expect((await alice.get("/")).location).toBe("/2fa/kurulum");
    expect((await alice.get("/ekip")).location).toBe("/2fa/kurulum");
    // Kurulumu tamamla (aynı oturumla)
    await alice.get("/2fa/kurulum");
    const page = await alice.get("/2fa/kurulum");
    expect(page.status).toBe(200);
    aliceSecret = await secretOf("alice@arcon.test");
    const done = await alice.post("/2fa/kurulum", { code: code(aliceSecret) });
    aliceCodes = recoveryCodes(done.text);
    expect(aliceCodes).toHaveLength(8);
    const home = await alice.get("/");
    expect(home.status).toBe(200);
    expect(home.text).toContain("ARCON");
    expect(home.text).toContain("Sahip");
  });

  it("davet bağlantısı ikinci kez kullanılamaz", async () => {
    const { token } = await createInvite(db, orgA, "tek@arcon.test", "viewer", null);
    const x = browser("10.0.0.9");
    await onboard(x, token, "tek@arcon.test");
    expect((await browser("10.0.0.10").get(`/davet/${token}`)).status).toBe(404);
  });

  it("organizasyonlar birbirinin sitesini göremez ve değiştiremez", async () => {
    expect((await alice.post("/sites", { url: "ornek.com", ownerConfirmed: "1" })).location).toMatch(/^\/site\/ornek-com\?m=/);
    const { token } = await createInvite(db, orgB, "bob@baska.test", "owner", null);
    await onboard(bob, token, "bob@baska.test");
    // Aynı alan adı başka organizasyonda ayrıca eklenebilir
    expect((await bob.post("/sites", { url: "ornek.com", ownerConfirmed: "1" })).location).toMatch(/^\/site\/ornek-com/);
    expect((await bob.post("/sites", { url: "gizli.com", name: "Gizli Proje", ownerConfirmed: "1" })).status).toBe(303);

    expect((await alice.get("/site/gizli-com")).status).toBe(404);
    expect((await alice.post("/site/gizli-com/delete")).status).toBe(404);
    const home = await alice.get("/");
    expect(home.text).not.toContain("Gizli Proje");
    // Bob kendi ornek-com'unu silince Alice'inki kalır
    await bob.post("/site/ornek-com/delete");
    expect((await alice.get("/site/ornek-com")).status).toBe(200);
    const { rows } = await db.query("SELECT org_id FROM sites WHERE slug = 'ornek-com'");
    expect(rows.map((r) => r.org_id)).toEqual([orgA]);
  });

  it("e-postayla ekip daveti; görüntüleyen sadece izler", async () => {
    const r = await alice.post("/ekip/davet", { email: "Carol@Arcon.test", role: "viewer" });
    expect(r.location).toMatch(/^\/ekip\?m=/);
    const mail = mails.find((m) => m.to[0] === "carol@arcon.test")!;
    expect(mail.html).toContain("ARCON");
    await onboard(carol, linkToken(mail.html), "carol@arcon.test");

    const home = await carol.get("/");
    expect(home.status).toBe(200);
    expect(home.text).toContain("ornek.com");
    expect(home.text).not.toContain('action="/sites"');
    expect((await carol.post("/sites", { url: "yeni.com", ownerConfirmed: "1" })).status).toBe(403);
    expect((await carol.post("/site/ornek-com/delete")).status).toBe(403);
    expect((await carol.get("/kayit")).status).toBe(403);
    expect((await carol.post("/ekip/davet", { email: "d@x.test", role: "viewer" })).status).toBe(403);
    expect((await db.query("SELECT 1 FROM sites WHERE slug = 'ornek-com'")).rowCount).toBe(1);
  });

  it("yönetici sahip davet edemez, sahibe dokunamaz; son sahip düşürülemez", async () => {
    const { rows } = await db.query<{ id: string }>("SELECT id FROM users WHERE email = 'alice@arcon.test'");
    const aliceId = rows[0].id;
    await alice.post(`/ekip/uye/${(await db.query<{ id: string }>("SELECT id FROM users WHERE email = 'carol@arcon.test'")).rows[0].id}/rol`, { role: "admin" });
    expect((await carol.post("/ekip/davet", { email: "o@x.test", role: "owner" })).status).toBe(403);
    expect((await carol.post(`/ekip/uye/${aliceId}/cikar`)).status).toBe(403);
    expect(await changeMember(db, orgA, aliceId, "viewer")).toEqual({ ok: false, error: "Organizasyonda en az bir sahip kalmalı" });
  });

  it("giriş: şifre + kod; aynı kod tekrar kullanılamaz; kurtarma kodu tek seferlik", async () => {
    await alice.post("/logout");
    expect((await alice.get("/")).location).toBe("/login");
    expect((await alice.post("/login", { email: "alice@arcon.test", password: "yanlis-sifre-123" })).status).toBe(401);
    expect((await alice.post("/login", { email: "alice@arcon.test", password: "Mavi-Kedi-Kosar-77" })).location).toBe("/2fa");
    expect((await alice.get("/")).location).toBe("/2fa");
    const s = await steps("alice@arcon.test", aliceSecret);
    expect((await alice.post("/2fa", { code: s.used })).status).toBe(401); // kurulumda kullanılmıştı
    expect((await alice.post("/2fa", { code: s.fresh })).location).toBe("/");

    await alice.post("/logout");
    await alice.post("/login", { email: "alice@arcon.test", password: "Mavi-Kedi-Kosar-77" });
    expect((await alice.post("/2fa", { recovery: aliceCodes[0].toUpperCase() })).location).toBe("/");
    await alice.post("/logout");
    await alice.post("/login", { email: "alice@arcon.test", password: "Mavi-Kedi-Kosar-77" });
    expect((await alice.post("/2fa", { recovery: aliceCodes[0] })).status).toBe(401);
    expect((await alice.post("/2fa", { recovery: aliceCodes[1] })).location).toBe("/");
  });

  it("başka kaynaktan gelen POST reddedilir (CSRF)", async () => {
    expect((await alice.post("/sites", { url: "csrf.com", ownerConfirmed: "1" }, "https://kotu.example")).status).toBe(403);
    expect((await db.query("SELECT 1 FROM sites WHERE slug = 'csrf-com'")).rowCount).toBe(0);
  });

  it("Bağlantı: secret bir kez gösterilir, olay gelince 'Bağlandı'; görüntüleyen anahtar yönetemez", async () => {
    const created = await alice.post("/site/ornek-com/anahtar/live/olustur");
    expect(created.status).toBe(200);
    expect(created.text).toContain("sadece şimdi gösteriliyor");
    const secret = created.text.match(/sg_live_sk_[A-Za-z0-9_-]{43}/)![0];
    const pk = created.text.match(/sg_live_pk_[A-Za-z0-9_-]+/)![0];

    const reload = await alice.get("/site/ornek-com");
    expect(reload.text).not.toContain(secret);
    expect(reload.text).toContain(pk);
    expect(reload.text).toContain("Bekleniyor");
    expect((await alice.post("/site/ornek-com/anahtar/live/olustur")).location).toMatch(/e=1$/); // zaten var

    const send = (sk: string) => {
      const body = JSON.stringify({ events: [{ type: "auth.failed", actor: "saldirgan@x.test" }] });
      return app(new Request(`${PUBLIC}/api/v1/events`, { method: "POST", headers: signRequest({ publicId: pk, secret: sk, body }), body }), { ip: "203.0.113.1" });
    };
    expect((await send(secret)).status).toBe(202);
    const after = await alice.get("/site/ornek-com");
    expect(after.text).toContain("Bağlandı");
    expect(after.text).toContain("saldirgan@x.test");
    expect((await alice.get("/")).text).toContain("Başarısız giriş");

    const { token } = await createInvite(db, orgA, "izleyici@arcon.test", "viewer", null);
    const v = browser("10.0.0.20");
    await onboard(v, token, "izleyici@arcon.test");
    const vp = await v.get("/site/ornek-com");
    expect(vp.text).toContain(pk);
    expect(vp.text).not.toContain("/anahtar/live/yenile");
    expect((await v.post("/site/ornek-com/anahtar/live/yenile")).status).toBe(403);
    expect((await v.post("/site/ornek-com/anahtar/live/iptal")).status).toBe(403);

    const rotated = await alice.post("/site/ornek-com/anahtar/live/yenile");
    const newSecret = rotated.text.match(/sg_live_sk_[A-Za-z0-9_-]{43}/)![0];
    expect(newSecret).not.toBe(secret);
    expect((await send(secret)).status).toBe(401);
    expect((await send(newSecret)).status).toBe(202);

    const dl = await browser("10.0.0.21").get("/istemci/sitegozcu.php");
    expect(dl.status).toBe(200);
    expect(dl.text).toContain("final class SiteGozcu");
  });

  it("5 hatalı şifrede hesap kilitlenir; erişim kaydı tutulur", async () => {
    const mallory = browser("10.0.0.66");
    for (let i = 0; i < 5; i++) await mallory.post("/login", { email: "bob@baska.test", password: `yanlis-${i}-xxxxxxx` });
    expect((await mallory.post("/login", { email: "bob@baska.test", password: "Mavi-Kedi-Kosar-77" })).status).toBe(429);
    await db.query("UPDATE users SET locked_until = NULL, failed_logins = 0 WHERE email = 'bob@baska.test'");

    const log = await alice.get("/kayit");
    expect(log.status).toBe(200);
    expect(log.text).toContain("Giriş yaptı");
    expect(log.text).toContain("Hatalı şifre");
    expect(log.text).toContain("Kurtarma koduyla giriş");
    expect(log.text).toContain("Davet gönderdi");
    expect(log.text).toContain("API anahtarı oluşturdu");
    expect(log.text).toContain("API secret&#39;ını yeniledi");
    // Başka organizasyonun kayıtları görünmez
    expect(log.text).not.toContain("bob@baska.test");
    // Her hatalı giriş kasıtlı olarak 0,4–0,8 sn bekletilir; 6 deneme varsayılan 5 sn sınırını aşabilir
  }, 20_000);

  it("yerel geliştirme: DEV_NO_AUTH sadece bu bilgisayardan gelen isteklerde girişi atlar", async () => {
    const dev = createApp({ cfg: { ...cfg, publicUrl: "http://127.0.0.1:3100", devNoAuth: true, devUser: "alice@arcon.test" }, db, monitor: { db, fetchFn: fakeFetch, mailer: null, publicUrl: PUBLIC }, mailer: null });
    const get = (ip: string, cookie = "", host = "127.0.0.1") => dev(new Request(`http://${host}:3100/`, { headers: { cookie } }), { ip });
    const r = await get("127.0.0.1");
    expect(r.status).toBe(303);
    const c = r.headers.get("set-cookie")!.split(";")[0];
    const home = await get("127.0.0.1", c);
    expect(home.status).toBe(200);
    expect(await home.text()).toContain("alice@arcon.test");
    // Başka bir bilgisayardan gelen istek için giriş istenir
    expect((await get("192.168.1.20")).headers.get("location")).toBe("/login");
    // localhost'tan gelen form da kabul edilir
    const post = await dev(new Request("http://localhost:3100/org/sec", { method: "POST", headers: { cookie: c, origin: "http://localhost:3100" }, body: new URLSearchParams({ org: orgA }) }), { ip: "127.0.0.1" });
    expect(post.status).toBe(303);
  });
});
