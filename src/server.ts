/**
 * Site Gözcü — Node.js giriş noktası: HTTP sunucusu + 5 dakikalık zamanlayıcı (node-cron).
 */
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import cron from "node-cron";
import { createApp, type AppDeps } from "./app";
import { pruneNonces } from "./apikeys";
import { pruneAppEvents } from "./app-events";
import { pruneOld } from "./audit";
import { loadConfig } from "./config";
import { createPool, migrate, type Db } from "./db";
import { createMailer, smtpReady } from "./mail";
import { runSite, type MonitorDeps } from "./monitor";
import { createSafeFetch } from "./net";
import { listActiveSites } from "./sites";

const MAX_BODY = 100_000;

class TooLarge extends Error {}

async function toRequest(req: IncomingMessage, base: string): Promise<Request> {
  const method = req.method ?? "GET";
  const headers = new Headers();
  for (const [k, v] of Object.entries(req.headers)) if (v !== undefined && k !== "host") headers.set(k, Array.isArray(v) ? v.join(", ") : v);
  let body: Buffer | undefined;
  if (method !== "GET" && method !== "HEAD") {
    const chunks: Buffer[] = [];
    let size = 0;
    for await (const c of req) {
      size += (c as Buffer).length;
      if (size > MAX_BODY) throw new TooLarge();
      chunks.push(c as Buffer);
    }
    body = Buffer.concat(chunks);
  }
  // İstek adresi her zaman PUBLIC_URL üzerinden kurulur (Host başlığına güvenilmez)
  const path = req.url?.startsWith("/") ? req.url : "/";
  return new Request(base + path, { method, headers, body });
}

function clientIp(req: IncomingMessage, trustProxy: boolean): string | null {
  if (trustProxy) {
    // Traefik, gördüğü adresi listenin sonuna ekler; baştaki değerler istemci tarafından uydurulabilir
    const xff = req.headers["x-forwarded-for"];
    const last = (Array.isArray(xff) ? xff.join(",") : xff ?? "").split(",").map((s) => s.trim()).filter(Boolean).pop();
    if (last) return last;
  }
  return req.socket.remoteAddress ?? null;
}

async function send(res: ServerResponse, r: Response): Promise<void> {
  res.statusCode = r.status;
  r.headers.forEach((v, k) => {
    if (k !== "set-cookie") res.setHeader(k, v);
  });
  const cookies = r.headers.getSetCookie();
  if (cookies.length) res.setHeader("set-cookie", cookies);
  res.end(Buffer.from(await r.arrayBuffer()));
}

/** Zamanlayıcı: duraklatılmamış siteleri 6'şarlı gruplar halinde çalıştırır (her site kendi sıklığına bakar). */
async function tick(monitor: MonitorDeps): Promise<void> {
  const sites = await listActiveSites(monitor.db);
  for (let i = 0; i < sites.length; i += 6) {
    const batch = sites.slice(i, i + 6);
    const res = await Promise.allSettled(batch.map((s) => runSite(monitor, s)));
    res.forEach((r, j) => {
      const id = `${batch[j].orgId.slice(0, 8)}/${batch[j].site.id}`;
      if (r.status === "rejected") console.error(`[${id}] kontrol hatası:`, r.reason);
      else if (!("skipped" in r.value)) console.log(`[${id}]`, JSON.stringify({ failing: r.value.failing, opened: r.value.opened, resolved: r.value.resolved }));
    });
  }
}

async function main(): Promise<void> {
  const cfg = loadConfig();
  const db: Db = createPool(cfg.databaseUrl);
  await migrate(db);
  const mailer = smtpReady(cfg) ? createMailer(cfg) : null;
  if (!mailer) console.warn("SMTP_PASS tanımlı değil: uyarı ve davet e-postaları gönderilmeyecek");
  if (cfg.allowPrivate) console.warn("ALLOW_PRIVATE=1: iç ağ adresleri izlenebilir — sadece yerel testte kullanın");
  if (cfg.devNoAuth) console.warn(`DEV_NO_AUTH=1: bu bilgisayardan açılınca giriş sorulmaz (${cfg.devUser ?? "ilk sahip"} olarak) — sadece yerel geliştirme`);
  const monitor: MonitorDeps = { db, fetchFn: createSafeFetch(cfg.allowPrivate), mailer, publicUrl: cfg.publicUrl };
  const deps: AppDeps = { cfg, db, monitor, mailer };
  const app = createApp(deps);

  const server = createServer(async (req, res) => {
    try {
      const request = await toRequest(req, cfg.publicUrl);
      await send(res, await app(request, { ip: clientIp(req, cfg.trustProxy) }));
    } catch (e) {
      if (e instanceof TooLarge) {
        res.writeHead(413).end("İstek çok büyük");
        return;
      }
      console.error("sunucu hatası:", e);
      if (!res.headersSent) res.writeHead(500).end("Sunucu hatası");
    }
  });
  server.headersTimeout = 20_000;
  server.requestTimeout = 60_000;
  server.listen(cfg.port, "0.0.0.0", () => console.log(`Site Gözcü dinliyor: :${cfg.port} · ${cfg.publicUrl}`));

  const tasks = cfg.cron
    ? [
        cron.schedule("*/5 * * * *", () => tick(monitor).catch((e) => console.error("zamanlayıcı hatası:", e)), { noOverlap: true, name: "kontroller" }),
        cron.schedule("*/5 * * * *", () => pruneNonces(db).catch((e) => console.error("nonce temizliği hatası:", e)), { name: "nonce" }),
        cron.schedule("17 3 * * *", () => Promise.all([pruneOld(db), pruneAppEvents(db)]).catch((e) => console.error("temizlik hatası:", e)), { name: "temizlik", timezone: "Europe/Istanbul" }),
      ]
    : [];

  const shutdown = (sig: string) => {
    console.log(`${sig} alındı, kapanıyor…`);
    for (const t of tasks) t.stop();
    server.close(() => void db.end().finally(() => process.exit(0)));
    setTimeout(() => process.exit(1), 10_000).unref();
  };
  process.on("SIGTERM", () => shutdown("SIGTERM"));
  process.on("SIGINT", () => shutdown("SIGINT"));
}

main().catch((e) => {
  console.error("başlatılamadı:", e instanceof Error ? e.message : e);
  process.exit(1);
});
