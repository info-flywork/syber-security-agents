/**
 * Olay alma API'si ve PHP / Node istemcileri.
 * İmza uyumluluğu testleri her zaman çalışır; veritabanı testleri TEST_DATABASE_URL ister (test veritabanı SIFIRLANIR).
 */
import { execFile, execFileSync } from "node:child_process";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { join } from "node:path";
import { promisify } from "node:util";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createOrg } from "../src/accounts";
import { canonicalString, createKey, deriveSigningKey, revokeKey, rotateKey, signRequest, signWithKey } from "../src/apikeys";
import { appRisk, appSummaries, parseEvents } from "../src/app-events";
import { createApp } from "../src/app";
import type { Config } from "../src/config";
import { createPool, migrate, type Db } from "../src/db";
import { addSite } from "../src/sites";
import { dashboard } from "../src/ui";
// @ts-expect-error — düz JavaScript istemci, tip bildirimi yok
import { SiteGozcu, deriveSigningKey as nodeDerive, signature as nodeSignature } from "../clients/node/sitegozcu.mjs";

const PHP_CLIENT = join(__dirname, "../clients/php/sitegozcu.php");
const hasPhp = (() => {
  try {
    execFileSync("php", ["-v"], { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
})();
const run = promisify(execFile);

const SECRET = "sg_live_sk_" + "A".repeat(43);
const FIXED = { ts: "1800000000", nonce: "abcdefghijklmnop", body: '{"events":[{"type":"auth.failed","actor":"çağrı@örnek.com"}]}' };

describe("imza uyumluluğu", () => {
  const expected = signWithKey(deriveSigningKey(SECRET), canonicalString(FIXED.ts, FIXED.nonce, "POST", "/api/v1/events", FIXED.body));

  it("Node istemcisi sunucuyla aynı imzayı üretir", () => {
    expect(nodeSignature(nodeDerive(SECRET), FIXED.ts, FIXED.nonce, "POST", "/api/v1/events", FIXED.body)).toBe(expected);
  });

  it.skipIf(!hasPhp)("PHP istemcisi sunucuyla aynı imzayı üretir (UTF-8 gövde dahil)", () => {
    const code = `require ${JSON.stringify(PHP_CLIENT)}; echo SiteGozcu::signature(SiteGozcu::deriveSigningKey($argv[1]), $argv[2], $argv[3], 'POST', '/api/v1/events', $argv[4]);`;
    const out = execFileSync("php", ["-r", code, "--", SECRET, FIXED.ts, FIXED.nonce, FIXED.body], { encoding: "utf8" });
    expect(out).toBe(expected);
  });

  it("gövde, zaman ya da nonce değişince imza değişir", () => {
    const k = deriveSigningKey(SECRET);
    expect(signWithKey(k, canonicalString(FIXED.ts, FIXED.nonce, "POST", "/api/v1/events", FIXED.body + " "))).not.toBe(expected);
    expect(signWithKey(k, canonicalString("1800000001", FIXED.nonce, "POST", "/api/v1/events", FIXED.body))).not.toBe(expected);
    expect(signWithKey(k, canonicalString(FIXED.ts, "abcdefghijklmnoq", "POST", "/api/v1/events", FIXED.body))).not.toBe(expected);
  });
});

describe("olay doğrulama", () => {
  it("türü, IP'yi, zamanı ve sınırları denetler", () => {
    expect(parseEvents({ events: [{ type: "auth.failed", ip: "203.0.113.5" }] })).toMatchObject({ ok: true });
    expect(parseEvents({ type: "app.error", message: "x" })).toMatchObject({ ok: true }); // tek nesne
    expect(parseEvents({ events: [] })).toEqual({ ok: true, events: [] }); // ping
    expect(parseEvents({ events: [{ type: "sql.drop" }] })).toMatchObject({ ok: false });
    expect(parseEvents({ events: [{ type: "auth.failed", ip: "999.1.1.1" }] })).toMatchObject({ ok: false });
    expect(parseEvents({ events: [{ type: "auth.failed", severity: "acil" }] })).toMatchObject({ ok: false });
    expect(parseEvents({ events: [{ type: "auth.failed", occurred_at: "2020-01-01T00:00:00Z" }] })).toMatchObject({ ok: false });
    expect(parseEvents({ events: Array.from({ length: 51 }, () => ({ type: "auth.failed" })) })).toMatchObject({ ok: false });
    const r = parseEvents({ events: [{ type: "auth.failed", actor: "a\u0000b".padEnd(500, "x") }] });
    expect(r.ok && r.events[0].actor).toHaveLength(120);
    expect(r.ok && r.events[0].actor?.includes("\u0000")).toBe(false);
  });
  it("risk katkısı: sadece live ve son 24 saat, en fazla 50", () => {
    const now = Date.now();
    const at = new Date(now).toISOString();
    expect(appRisk([{ severity: "high", mode: "live", occurredAt: at }, { severity: "info", mode: "live", occurredAt: at }], now)).toBe(6);
    expect(appRisk([{ severity: "critical", mode: "test", occurredAt: at }], now)).toBe(0);
    expect(appRisk([{ severity: "critical", mode: "live", occurredAt: new Date(now - 25 * 3600_000).toISOString() }], now)).toBe(0);
    expect(appRisk(Array.from({ length: 10 }, () => ({ severity: "critical" as const, mode: "live" as const, occurredAt: at })), now)).toBe(50);
  });
});

const DB_URL = process.env.TEST_DATABASE_URL;
const PUBLIC = "http://panel.test";
const cfg: Config = {
  databaseUrl: DB_URL ?? "",
  publicUrl: PUBLIC,
  port: 0,
  appSecret: "s".repeat(40),
  trustProxy: false,
  allowPrivate: false,
  cron: false,
  smtp: { host: "", port: 465, secure: "tls", user: "", pass: "", from: "x@panel.test", fromName: "" },
};

describe.skipIf(!DB_URL)("POST /api/v1/events (PostgreSQL)", () => {
  let db: Db;
  let app: ReturnType<typeof createApp>;
  let siteA = "";
  let siteB = "";
  let liveA = { publicId: "", secret: "" };
  let testA = { publicId: "", secret: "" };
  let liveB = { publicId: "", secret: "" };
  let server: Server;
  let baseUrl = "";

  const post = (body: string, headers: Record<string, string>, ip = "198.51.100.1") =>
    app(new Request(`${PUBLIC}/api/v1/events`, { method: "POST", headers: { "content-type": "application/json", ...headers }, body }), { ip });
  const send = async (key: { publicId: string; secret: string }, events: unknown[], o: { timestamp?: number; nonce?: string; ip?: string } = {}) => {
    const body = JSON.stringify({ events });
    const res = await post(body, signRequest({ ...key, body, ...o }), o.ip);
    return { status: res.status, json: (await res.json()) as Record<string, unknown> };
  };
  const count = async (siteUuid: string, extra = "") => (await db.query(`SELECT count(*)::int AS n FROM app_events WHERE site_uuid = $1 ${extra}`, [siteUuid])).rows[0].n as number;

  beforeAll(async () => {
    db = createPool(DB_URL!);
    await db.query("DROP SCHEMA public CASCADE; CREATE SCHEMA public;");
    await migrate(db);
    app = createApp({ cfg, db, monitor: { db, fetchFn: fetch as never, mailer: null, publicUrl: PUBLIC }, mailer: null, ingestLimits: { perKey: 30 } });
    const orgA = await createOrg(db, "A");
    const orgB = await createOrg(db, "B");
    const site = (id: string) => ({ id, name: id, origin: `https://${id}.test`, pages: ["/"], extraPaths: [], emails: [], intervalMin: 15 as const, paused: false, createdAt: "", ownerConfirmed: true as const });
    siteA = ((await addSite(db, orgA, site("a"))) as { row: { uuid: string } }).row.uuid;
    siteB = ((await addSite(db, orgB, site("b"))) as { row: { uuid: string } }).row.uuid;
    const mk = async (s: string, mode: "live" | "test") => {
      const r = (await createKey(db, s, mode, cfg.appSecret, null))!;
      return { publicId: r.key.publicId, secret: r.secret };
    };
    liveA = await mk(siteA, "live");
    testA = await mk(siteA, "test");
    liveB = await mk(siteB, "live");

    // PHP istemcisi için gerçek bir HTTP sunucusu (server.ts'teki dönüştürmenin küçük hâli)
    server = createServer(async (req, res) => {
      const chunks: Buffer[] = [];
      for await (const c of req) chunks.push(c as Buffer);
      const headers = new Headers();
      for (const [k, v] of Object.entries(req.headers)) if (typeof v === "string") headers.set(k, v);
      const r = await app(new Request(PUBLIC + req.url, { method: req.method, headers, body: req.method === "POST" ? Buffer.concat(chunks) : undefined }), { ip: "127.0.0.1" });
      res.writeHead(r.status, { "content-type": r.headers.get("content-type") ?? "text/plain" }).end(Buffer.from(await r.arrayBuffer()));
    });
    await new Promise<void>((ok) => server.listen(0, "127.0.0.1", ok));
    baseUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  });
  afterAll(async () => {
    server?.close();
    await db?.end();
  });

  it("imzalı olay kabul edilir ve anahtarın kendi varlığına yazılır", async () => {
    const r = await send(liveA, [{ type: "auth.failed", actor: "ali@a.test", ip: "203.0.113.9", path: "/giris" }]);
    expect(r).toEqual({ status: 202, json: { accepted: 1, mode: "live" } });
    expect(await count(siteA)).toBe(1);
    // Gövdede başka varlık belirtilse bile olay anahtarın varlığına yazılır
    await send(liveB, [{ type: "access.denied", site: siteA, site_uuid: siteA } as unknown]);
    expect(await count(siteA)).toBe(1);
    expect(await count(siteB)).toBe(1);
  });

  it("secret veritabanında saklanmaz", async () => {
    const { rows } = await db.query("SELECT row_to_json(k)::text AS t FROM site_keys k");
    const all = rows.map((r) => r.t).join("\n");
    for (const k of [liveA, testA, liveB]) {
      expect(all).not.toContain(k.secret);
      expect(all).not.toContain(deriveSigningKey(k.secret).toString("base64"));
      expect(all).not.toContain(deriveSigningKey(k.secret).toString("hex"));
    }
  });

  it("yanlış secret, bilinmeyen Site ID ve değiştirilmiş gövde reddedilir", async () => {
    expect((await send({ publicId: liveA.publicId, secret: liveB.secret }, [{ type: "auth.failed" }])).status).toBe(401);
    const unknown = await send({ publicId: "sg_live_pk_bilinmeyenbilinmeyen", secret: liveA.secret }, [{ type: "auth.failed" }]);
    expect(unknown).toEqual({ status: 401, json: { error: "imza geçersiz" } });
    const headers = signRequest({ ...liveA, body: JSON.stringify({ events: [{ type: "auth.failed" }] }) });
    const tampered = await post(JSON.stringify({ events: [{ type: "app.error" }] }), headers);
    expect(tampered.status).toBe(401);
    expect(await count(siteA)).toBe(1);
  });

  it("5 dakikalık pencere dışındaki zaman damgası reddedilir", async () => {
    const now = Math.floor(Date.now() / 1000);
    expect((await send(liveA, [], { timestamp: now - 301 })).status).toBe(401);
    expect((await send(liveA, [], { timestamp: now + 301 })).status).toBe(401);
    expect((await send(liveA, [], { timestamp: now - 290 })).status).toBe(202);
  });

  it("aynı istek tekrar gönderilemez (nonce)", async () => {
    const body = JSON.stringify({ events: [{ type: "request.suspicious", message: "union select" }] });
    const h = signRequest({ ...liveA, body });
    expect((await post(body, h)).status).toBe(202);
    expect((await post(body, h)).status).toBe(409);
    expect(await count(siteA, "AND type = 'request.suspicious'")).toBe(1);
  });

  it("boş gönderim bağlantı testidir: olay yazmaz, anahtarı 'bağlandı' yapar", async () => {
    const before = await count(siteB);
    expect((await send(liveB, [])).status).toBe(202);
    expect(await count(siteB)).toBe(before);
    const { rows } = await db.query("SELECT last_used_at FROM site_keys WHERE public_id = $1", [liveB.publicId]);
    expect(rows[0].last_used_at).not.toBe(null);
  });

  it("geçersiz gövde 400 döner", async () => {
    expect((await send(liveA, [{ type: "bilinmeyen" }])).status).toBe(400);
    const body = "{bozuk";
    expect((await post(body, signRequest({ ...liveA, body }))).status).toBe(400);
    expect((await post("{}", { "x-sg-site": liveA.publicId })).status).toBe(400);
  });

  it("yenileme: Site ID aynı kalır, eski secret geçersiz olur; iptal: anahtar kalıcı olarak kapanır", async () => {
    const r = (await rotateKey(db, siteA, "test", cfg.appSecret))!;
    expect(r.key.publicId).toBe(testA.publicId);
    expect((await send(testA, [])).status).toBe(401);
    testA = { publicId: r.key.publicId, secret: r.secret };
    expect((await send(testA, [{ type: "app.error", severity: "critical" }])).status).toBe(202);

    expect(await revokeKey(db, siteA, "test")).toBe(true);
    expect((await send(testA, [])).status).toBe(401);
    const again = (await createKey(db, siteA, "test", cfg.appSecret, null))!;
    expect(again.key.publicId).not.toBe(testA.publicId);
    testA = { publicId: again.key.publicId, secret: again.secret };
  });

  it("test anahtarının olayları akışta TEST olarak görünür, risk puanına yansımaz", async () => {
    await send(testA, Array.from({ length: 5 }, () => ({ type: "access.denied", severity: "critical" })));
    await send(liveA, [{ type: "access.denied" }, { type: "access.denied" }]);
    const sums = await appSummaries(db, [siteA]);
    const a = sums.get(siteA)!;
    // live: auth.failed (0.5) + request.suspicious (5) + 2 × access.denied (5) = 15.5 → 16; test olayları sayılmaz
    expect(a.risk).toBe(16);
    expect(a.counts24["access.denied"]).toBe(2);
    expect(a.lastSeen).not.toBe(null);
    const { rows } = await db.query("SELECT config, state FROM sites WHERE uuid = $1", [siteA]);
    const html = dashboard([{ site: rows[0].config, st: rows[0].state, app: a }], null, false);
    expect(html).toContain("Yetkisiz erişim denemesi");
    expect(html).toContain(">TEST<");
    expect(html).toContain("uygulama olayları 16");
  });

  it("anahtar başına istek sınırı", async () => {
    const r = (await createKey(db, siteB, "test", cfg.appSecret, null))!;
    const k = { publicId: r.key.publicId, secret: r.secret };
    const codes: number[] = [];
    for (let i = 0; i < 31; i++) codes.push((await send(k, [])).status);
    expect(codes.slice(0, 30).every((c) => c === 202)).toBe(true);
    expect(codes[30]).toBe(429);
  });

  it("Node istemcisi olay gönderir; hata durumunda fırlatmaz", async () => {
    const viaApp = ((url: string, init: RequestInit) => app(new Request(url.replace(/^https?:\/\/[^/]+/, PUBLIC), init), { ip: "198.51.100.7" })) as typeof fetch;
    const client = new SiteGozcu({ siteId: liveB.publicId, secret: liveB.secret, url: "https://panel.test", fetch: viaApp });
    const before = await count(siteB);
    expect(await client.failedLogin("veli@b.test", { ip: "203.0.113.20", path: "/giris" })).toBe(true);
    expect(await client.appError(new TypeError("x tanımsız"))).toBe(true);
    expect(await count(siteB)).toBe(before + 2);
    const { rows } = await db.query("SELECT message FROM app_events WHERE site_uuid = $1 AND type = 'app.error' ORDER BY id DESC LIMIT 1", [siteB]);
    expect(rows[0].message).toMatch(/^TypeError: x tanımsız/);

    const wrong = new SiteGozcu({ siteId: liveB.publicId, secret: liveA.secret, url: "https://panel.test", fetch: viaApp });
    expect(await wrong.failedLogin("x")).toBe(false);
    expect(wrong.lastError).toBe("HTTP 401: imza geçersiz");
    const down = new SiteGozcu({ siteId: liveB.publicId, secret: liveB.secret, url: "http://127.0.0.1:1", timeoutMs: 500 });
    expect(await down.ping()).toBe(false);
    expect(down.lastError).toBeTruthy();
  });

  it.skipIf(!hasPhp)("PHP istemcisi gerçek HTTP üzerinden olay gönderir ve bağlantıyı test eder", async () => {
    const env = { ...process.env, SITEGOZCU_SITE_ID: liveA.publicId, SITEGOZCU_SECRET: liveA.secret, SITEGOZCU_URL: baseUrl };
    const t = await run("php", [PHP_CLIENT, "test"], { env });
    expect(t.stdout).toContain("Bağlantı başarılı");

    const before = await count(siteA);
    const code = `require ${JSON.stringify(PHP_CLIENT)}; $g = SiteGozcu::fromEnv();
      $ok = $g->failedLogin('ayşe@a.test', ['ip' => '203.0.113.30', 'path' => '/giris'])
        && $g->accessDenied('/yonetim')
        && $g->appError(new RuntimeException('veritabanı yok'));
      echo $ok ? 'ok' : $g->lastError;`;
    const r = await run("php", ["-r", code], { env });
    expect(r.stdout).toBe("ok");
    expect(await count(siteA)).toBe(before + 3);
    const { rows } = await db.query("SELECT actor FROM app_events WHERE site_uuid = $1 AND type = 'auth.failed' ORDER BY id DESC LIMIT 1", [siteA]);
    expect(rows[0].actor).toBe("ayşe@a.test");

    const bad = await run("php", [PHP_CLIENT, "test"], { env: { ...env, SITEGOZCU_SECRET: liveB.secret } }).catch((e) => e);
    expect(bad.code).toBe(1);
    expect(bad.stderr).toContain("imza geçersiz");
  });
});
