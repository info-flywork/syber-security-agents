/**
 * HTTP yönlendirici (fetch tarzı: Request → Response). Node sunucusu server.ts'te.
 * Her panel isteği oturumdaki organizasyonla sınırlanır; yetki kuralları accounts.ts'teki `can`.
 */
import { readFileSync } from "node:fs";
import { join } from "node:path";
import QRCode from "qrcode";
import { esc } from "./alert";
import {
  ROLES,
  ROLE_LABEL,
  acceptInvite,
  can,
  changeMember,
  consumeRecoveryCode,
  createInvite,
  createUser,
  enableTotp,
  findInvite,
  findUserByEmail,
  getRole,
  getUser,
  isLocked,
  listMembers,
  listMemberships,
  listPendingInvites,
  normalizeEmail,
  recordTotpStep,
  registerFailure,
  registerSuccess,
  revokeInvite,
  setPassword,
  setPendingTotp,
  validEmail,
  type Role,
  type User,
} from "./accounts";
import { createKey, listActiveKeys, revokeKey, rotateKey, type KeyMode } from "./apikeys";
import { appSummaries } from "./app-events";
import { audit, listAudit, type AuditEntry } from "./audit";
import {
  RateLimiter,
  cookieName,
  createSession,
  destroyOtherSessions,
  destroySession,
  loadSession,
  readCookie,
  safeNext,
  sameOrigin,
  sessionCookie,
  setSessionOrg,
  upgradeSession,
  type Session,
} from "./auth";
import type { Config } from "./config";
import type { Db } from "./db";
import type { Mailer } from "./mail";
import { initialState, resetBaseline, runSite, sendTestMail, type MonitorDeps, type RunSummary } from "./monitor";
import {
  burnPasswordTime,
  decryptSecret,
  encryptSecret,
  hashPassword,
  newRecoveryCodes,
  newTotpSecret,
  normalizeRecovery,
  otpauthUrl,
  passwordProblem,
  sha256,
  verifyPassword,
  verifyTotp,
} from "./security";
import { parseSiteInput, type SiteInput } from "./site-input";
import { addSite, getSite, listSites, removeSite, updateSite, type SiteRow } from "./sites";
import { dashboard, layout, loginPage, siteDetail, siteHealth, type PanelCtx } from "./ui";
import { accountPage, auditPage, invitePage, recoveryCodesPage, teamPage, totpPage, totpSetupPage } from "./ui-account";
import { connectionSection, revealBox, type Revealed } from "./ui-connect";
import { INGEST_PATH, createIngest } from "./ingest";

export interface AppDeps {
  cfg: Config;
  db: Db;
  monitor: MonitorDeps;
  mailer: Mailer | null;
  /** PHP / Node istemci dosyalarının klasörü (varsayılan: ./clients) */
  clientsDir?: string;
  /** Testlerde olay API'sinin istek sınırlarını küçültmek için */
  ingestLimits?: { perIp?: number; perKey?: number };
}

/** İndirilebilir istemciler: yol → [klasördeki dosya, içerik türü] */
const CLIENT_FILES: Record<string, [string, string]> = {
  "/istemci/sitegozcu.php": ["php/sitegozcu.php", "text/plain; charset=utf-8"],
  "/istemci/sitegozcu.mjs": ["node/sitegozcu.mjs", "text/plain; charset=utf-8"],
};

export interface RequestMeta {
  ip: string | null;
}

type Handler = (req: Request, meta: RequestMeta) => Promise<Response>;

const CSP = "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'";

const withMsg = (path: string, msg: string, err = false) => `${path}${path.includes("?") ? "&" : "?"}m=${encodeURIComponent(msg)}${err ? "&e=1" : ""}`;

async function formData(req: Request): Promise<Record<string, string>> {
  const fd = await req.formData();
  const out: Record<string, string> = {};
  for (const [k, v] of fd.entries()) if (typeof v === "string") out[k] = v;
  return out;
}

function summarize(r: RunSummary | { skipped: string }): string {
  if ("skipped" in r) return `Atlandı: ${r.skipped}`;
  const mail = typeof r.mail === "string" ? r.mail : r.mail?.ok ? "e-posta gönderildi" : `e-posta gönderilemedi: ${r.mail?.error}`;
  return `Kontrol tamam: ${r.checks} kontrol, ${r.failing} sorun/öneri · ${r.opened.length} yeni, ${r.resolved.length} düzeldi · ${mail}`;
}

function inviteMail(orgName: string, role: Role, inviter: string, link: string): { subject: string; html: string } {
  return {
    subject: `${orgName} — Site Gözcü daveti`,
    html: `<div style="font-family:Arial,sans-serif;font-size:14px;color:#111;max-width:560px">
<h2 style="margin:0 0 8px">Site Gözcü'ye davet edildiniz</h2>
<p><b>${esc(inviter)}</b>, sizi <b>${esc(orgName)}</b> organizasyonuna <b>${ROLE_LABEL[role]}</b> olarak davet etti.</p>
<p><a href="${esc(link)}" style="display:inline-block;background:#0284c7;color:#fff;padding:10px 18px;border-radius:8px;text-decoration:none">Daveti kabul et</a></p>
<p style="color:#666">Bağlantı 7 gün geçerlidir ve bir kez kullanılabilir. Bu daveti beklemiyorsanız e-postayı yok sayın.</p></div>`,
  };
}

export function createApp(deps: AppDeps): Handler {
  const { cfg, db, monitor } = deps;
  const publicOrigin = new URL(cfg.publicUrl).origin;
  // Yerel geliştirmede panel hem 127.0.0.1 hem localhost adresinden açılabilsin
  const devPort = new URL(cfg.publicUrl).port;
  const allowedOrigins = cfg.devNoAuth ? [`http://127.0.0.1:${devPort}`, `http://localhost:${devPort}`].map((o) => o.replace(/:$/, "")) : [publicOrigin];
  const isLoopback = (ip: string | null) => ip === "127.0.0.1" || ip === "::1" || ip === "::ffff:127.0.0.1";
  const secure = publicOrigin.startsWith("https:");
  const cookie = cookieName(secure);

  const loginLimit = new RateLimiter(20, 15 * 60_000); // IP başına
  const totpLimit = new RateLimiter(10, 15 * 60_000); // oturum başına
  const inviteLimit = new RateLimiter(30, 60 * 60_000); // organizasyon başına
  const registerLimit = new RateLimiter(10, 60 * 60_000); // IP başına
  const ingest = createIngest({ db, appSecret: cfg.appSecret, limits: deps.ingestLimits });
  const clientsDir = deps.clientsDir ?? join(process.cwd(), "clients");

  const headers = (extra: Record<string, string> = {}) => ({
    "content-security-policy": CSP,
    "x-frame-options": "DENY",
    "x-content-type-options": "nosniff",
    "referrer-policy": "same-origin",
    "cache-control": "no-store",
    ...(secure ? { "strict-transport-security": "max-age=31536000" } : {}),
    ...extra,
  });
  const html = (body: string, status = 200, extra: Record<string, string> = {}) =>
    new Response(body, { status, headers: headers({ "content-type": "text/html; charset=utf-8", ...extra }) });
  const redirect = (to: string, extra: Record<string, string> = {}) => new Response(null, { status: 303, headers: headers({ location: to, ...extra }) });
  const setC = (token: string) => ({ "set-cookie": sessionCookie(token, secure) });
  const clearC = () => ({ "set-cookie": sessionCookie("", secure, true) });
  const errorPage = (status: number, text: string) => html(layout("Hata", `<div class="center"><div class="card"><p style="margin:0">${esc(text)}</p><p style="margin:12px 0 0"><a href="/">Ana sayfa</a></p></div></div>`), status);

  /** Kısmi oturumu doğru adıma yönlendir. */
  const stageHome = (s: Session | null) => (!s ? "/login" : s.stage === "totp" ? "/2fa" : s.stage === "setup" ? "/2fa/kurulum" : "/");

  async function handle(req: Request, meta: RequestMeta): Promise<Response> {
    const url = new URL(req.url);
    const path = url.pathname;
    const isPost = req.method === "POST";
    const ip = meta.ip;
    const ua = req.headers.get("user-agent");
    const log = (e: AuditEntry) => audit(db, { ip, userAgent: ua, ...e });

    if (path === "/healthz") {
      await db.query("SELECT 1");
      return new Response("ok", { headers: { "content-type": "text/plain", "cache-control": "no-store" } });
    }
    // Uygulamalardan imzalı olay alma: oturum ve CSRF kontrolü yerine HMAC imzası
    if (path === INGEST_PATH) return ingest(req, ip);
    // İstemci dosyaları herkese açık (gizli bilgi içermez)
    const client = CLIENT_FILES[path];
    if (client && req.method === "GET") {
      try {
        return new Response(readFileSync(join(clientsDir, client[0])), {
          headers: headers({ "content-type": client[1], "content-disposition": `attachment; filename="${path.split("/").pop()}"`, "cache-control": "public, max-age=300" }),
        });
      } catch {
        return errorPage(404, "İstemci dosyası bulunamadı.");
      }
    }
    if (req.method !== "GET" && req.method !== "POST") return errorPage(405, "Desteklenmeyen istek.");
    if (isPost && !allowedOrigins.some((o) => sameOrigin(req, o))) return errorPage(403, "Geçersiz istek kaynağı.");

    const sess = await loadSession(db, readCookie(req.headers.get("cookie"), cookie));

    // Yerel geliştirme: bu bilgisayardan gelen GET isteklerinde giriş sorulmaz (DEV_NO_AUTH=1, config.ts'te yerelle sınırlı)
    if (cfg.devNoAuth && !isPost && isLoopback(ip) && sess?.stage !== "full") {
      const { rows } = cfg.devUser
        ? await db.query<{ id: string }>("SELECT id FROM users WHERE email = $1", [cfg.devUser.toLowerCase()])
        : await db.query<{ id: string }>("SELECT u.id FROM users u JOIN memberships m ON m.user_id = u.id WHERE m.role = 'owner' ORDER BY u.created_at LIMIT 1");
      if (rows[0]) {
        if (sess) await destroySession(db, sess.tokenHash);
        const orgs = await listMemberships(db, rows[0].id);
        const token = await createSession(db, rows[0].id, orgs[0]?.orgId ?? null, "full", ip, ua);
        const back = path === "/login" || path.startsWith("/2fa") ? "/" : path + url.search;
        return redirect(back, setC(token));
      }
    }
    const msg = url.searchParams.get("m");
    const isErr = url.searchParams.get("e") === "1";

    // ——— Giriş ———
    if (path === "/login") {
      if (!isPost) {
        if (sess) return redirect(stageHome(sess));
        return html(loginPage(msg, url.searchParams.get("email") ?? "", url.searchParams.get("next") ?? ""));
      }
      const fd = await formData(req);
      const email = normalizeEmail(fd.email ?? "").slice(0, 254);
      const next = safeNext(fd.next ?? null);
      const fail = async (text: string, status = 401) => {
        await new Promise((r) => setTimeout(r, 400 + Math.random() * 400));
        return html(loginPage(text, email, next === "/" ? "" : next), status);
      };
      if (!loginLimit.allow(`ip:${ip}`)) return fail("Çok fazla deneme yapıldı. 15 dakika sonra tekrar deneyin.", 429);
      const password = fd.password ?? "";
      const user = email ? await findUserByEmail(db, email) : null;
      if (!user) {
        await burnPasswordTime(password);
        await log({ email: email || null, action: "login.unknown" });
        return fail("E-posta ya da şifre hatalı.");
      }
      if (isLocked(user)) {
        await burnPasswordTime(password);
        await log({ userId: user.id, email: user.email, action: "login.locked" });
        return fail("Çok fazla hatalı deneme nedeniyle hesap geçici olarak kilitlendi. 15 dakika sonra tekrar deneyin.", 429);
      }
      if (!(await verifyPassword(password, user.password_hash))) {
        await registerFailure(db, user.id);
        await log({ userId: user.id, email: user.email, action: "login.fail" });
        return fail("E-posta ya da şifre hatalı.");
      }
      if (sess) await destroySession(db, sess.tokenHash);
      const stage = user.totp_enabled ? "totp" : "setup";
      const token = await createSession(db, user.id, null, stage, ip, ua);
      const nextQ = next === "/" ? "" : `?next=${encodeURIComponent(next)}`;
      return redirect((stage === "totp" ? "/2fa" : "/2fa/kurulum") + nextQ, setC(token));
    }

    if (path === "/logout" && isPost) {
      if (sess) {
        await destroySession(db, sess.tokenHash);
        await log({ userId: sess.userId, email: sess.email, orgId: sess.orgId, action: "logout" });
      }
      return redirect("/login", clearC());
    }

    // ——— İki adımlı doğrulama ———
    if (path === "/2fa") {
      if (!sess || sess.stage !== "totp") return redirect(stageHome(sess));
      if (!isPost) return html(totpPage(null));
      const user = await getUser(db, sess.userId);
      if (!user?.totp_secret || isLocked(user)) {
        await destroySession(db, sess.tokenHash);
        return redirect(withMsg("/login", "Hesap geçici olarak kilitli. 15 dakika sonra tekrar deneyin.", true), clearC());
      }
      if (!totpLimit.allow(sess.tokenHash)) return html(totpPage("Çok fazla deneme. Bir süre sonra tekrar giriş yapın."), 429);
      const fd = await formData(req);
      let ok = false;
      let viaRecovery = false;
      if (fd.recovery) {
        ok = await consumeRecoveryCode(db, user.id, sha256(normalizeRecovery(fd.recovery)));
        viaRecovery = ok;
      } else {
        const step = verifyTotp(decryptSecret(user.totp_secret, cfg.appSecret), fd.code ?? "", Number(user.totp_last_step));
        ok = step !== null && (await recordTotpStep(db, user.id, step));
      }
      if (!ok) {
        await registerFailure(db, user.id);
        await log({ userId: user.id, email: user.email, action: "totp.fail" });
        return html(totpPage(fd.recovery ? "Kurtarma kodu geçersiz ya da kullanılmış." : "Kod hatalı ya da süresi geçmiş. Uygulamadaki güncel kodu girin."), 401);
      }
      return finishLogin(sess, user, url.searchParams.get("next"), viaRecovery);
    }

    if (path === "/2fa/kurulum") {
      if (!sess || sess.stage !== "setup") return redirect(stageHome(sess));
      const user = await getUser(db, sess.userId);
      if (!user) return redirect("/login", clearC());
      if (!user.totp_secret) {
        await setPendingTotp(db, user.id, encryptSecret(newTotpSecret(), cfg.appSecret));
        return redirect(path + url.search);
      }
      const secret = decryptSecret(user.totp_secret, cfg.appSecret);
      if (!isPost) {
        const svg = (await QRCode.toString(otpauthUrl(secret, user.email), { type: "svg", margin: 1, errorCorrectionLevel: "M" })).replace("<svg ", '<svg width="196" height="196" ');
        return html(totpSetupPage(svg, secret, user.email, msg));
      }
      if (!totpLimit.allow(sess.tokenHash)) return redirect(withMsg(path, "Çok fazla deneme. Bir süre sonra tekrar giriş yapın.", true));
      const fd = await formData(req);
      const step = verifyTotp(secret, fd.code ?? "", Number(user.totp_last_step));
      if (step === null) return redirect(withMsg(path + url.search, "Kod hatalı. Uygulamada görünen güncel 6 haneli kodu girin; telefonun saati doğru olmalı.", true));
      const codes = newRecoveryCodes();
      await enableTotp(db, user.id, step, codes.map((c) => sha256(normalizeRecovery(c))));
      await log({ userId: user.id, email: user.email, action: "totp.enabled" });
      const res = await finishLogin(sess, user, url.searchParams.get("next"), false);
      return html(recoveryCodesPage(codes, safeNext(url.searchParams.get("next"))), 200, { "set-cookie": res.headers.get("set-cookie")! });
    }

    async function finishLogin(s: Session, user: User, next: string | null, viaRecovery: boolean): Promise<Response> {
      await registerSuccess(db, user.id);
      const orgs = await listMemberships(db, user.id);
      const orgId = orgs[0]?.orgId ?? null;
      const token = await upgradeSession(db, s, orgId, ip, ua);
      await log({ userId: user.id, email: user.email, orgId, action: viaRecovery ? "totp.recovery" : "login.ok" });
      return redirect(safeNext(next), setC(token));
    }

    // ——— Davet ———
    const inv = path.match(/^\/davet\/([A-Za-z0-9_-]{20,100})$/);
    if (inv) {
      const token = inv[1];
      const invite = await findInvite(db, token);
      if (!invite) return html(invitePage({ kind: "invalid" }), 404);
      if (sess?.stage === "full") {
        if (sess.email !== invite.email) return html(invitePage({ kind: "wrong-account", invite, email: sess.email }, token));
        if (!isPost) return html(invitePage({ kind: "accept", invite, error: null }, token));
        if (!(await acceptInvite(db, invite.id, sess.userId))) return html(invitePage({ kind: "invalid" }), 410);
        await setSessionOrg(db, sess.tokenHash, invite.orgId);
        await log({ userId: sess.userId, email: sess.email, orgId: invite.orgId, action: "invite.accepted", target: ROLE_LABEL[invite.role] });
        return redirect(withMsg("/", `${invite.orgName} organizasyonuna katıldınız.`));
      }
      const existing = await findUserByEmail(db, invite.email);
      if (existing) return html(invitePage({ kind: "login", invite, token }, token));
      if (!isPost) return html(invitePage({ kind: "register", invite, error: null }, token));
      if (!registerLimit.allow(`ip:${ip}`)) return html(invitePage({ kind: "register", invite, error: "Çok fazla deneme. Bir saat sonra tekrar deneyin." }, token), 429);
      const fd = await formData(req);
      const pw = fd.password ?? "";
      const problem = pw !== (fd.password2 ?? "") ? "Şifreler aynı değil" : passwordProblem(pw, invite.email);
      if (problem) return html(invitePage({ kind: "register", invite, error: problem }, token), 400);
      let user: User;
      try {
        user = await createUser(db, invite.email, await hashPassword(pw));
      } catch {
        return html(invitePage({ kind: "login", invite, token }, token), 409);
      }
      if (!(await acceptInvite(db, invite.id, user.id))) return html(invitePage({ kind: "invalid" }), 410);
      await log({ userId: user.id, email: user.email, orgId: invite.orgId, action: "invite.accepted", target: ROLE_LABEL[invite.role] });
      if (sess) await destroySession(db, sess.tokenHash);
      const st = await createSession(db, user.id, invite.orgId, "setup", ip, ua);
      return redirect("/2fa/kurulum", setC(st));
    }

    // ——— Buradan sonrası tam oturum ister ———
    if (!sess || sess.stage !== "full") {
      if (req.method === "GET") return redirect(sess ? stageHome(sess) : path === "/" ? "/login" : `/login?next=${encodeURIComponent(safeNext(path))}`);
      return errorPage(401, "Oturum süresi doldu, tekrar giriş yapın.");
    }

    const orgs = await listMemberships(db, sess.userId);
    if (!orgs.length) return html(layout("Üyelik yok", `<div class="center"><div class="card"><p style="margin:0">Hiçbir organizasyona üye değilsiniz. Organizasyon sahibinden davet isteyin.</p><form method="post" action="/logout" style="margin-top:12px"><button>Çıkış</button></form></div></div>`, {}), 403);
    let current = orgs.find((o) => o.orgId === sess.orgId);
    if (!current) {
      current = orgs[0];
      await setSessionOrg(db, sess.tokenHash, current.orgId);
    }
    const orgId = current.orgId;
    const role = current.role;
    const act = (action: string, target?: string | null, detail?: Record<string, unknown>) => log({ userId: sess.userId, email: sess.email, orgId, action, target, detail });
    const deny = async (what: string) => {
      await act("access.denied", what);
      return errorPage(403, "Bu işlem için yetkiniz yok.");
    };

    const rows = await listSites(db, orgId);
    const ctx: PanelCtx = {
      email: sess.email,
      role,
      orgId,
      orgName: current.orgName,
      orgs: orgs.map((o) => ({ id: o.orgId, name: o.orgName })),
      sites: rows.map(({ site, st }) => ({ id: site.id, name: site.name, health: siteHealth(site, st) })),
    };

    if (path === "/" && !isPost) {
      const sums = await appSummaries(db, rows.map((r) => r.uuid));
      return html(dashboard(rows.map((r) => ({ site: r.site, st: r.st, app: sums.get(r.uuid) })), msg, isErr, {}, ctx));
    }

    if (path === "/org/sec" && isPost) {
      const { org = "" } = await formData(req);
      const target = orgs.find((o) => o.orgId === org);
      if (!target) return deny("organizasyon değiştirme");
      await setSessionOrg(db, sess.tokenHash, target.orgId);
      await log({ userId: sess.userId, email: sess.email, orgId: target.orgId, action: "org.switch", target: target.orgName });
      return redirect("/");
    }

    if (path === "/sites" && isPost) {
      if (!can.manageSites(role)) return deny("site ekleme");
      const parsed = parseSiteInput((await formData(req)) as unknown as SiteInput, { allowPrivate: cfg.allowPrivate });
      if (!parsed.ok) return redirect(withMsg("/#ekle", parsed.error, true));
      const added = await addSite(db, orgId, parsed.site);
      if (!added.ok) return redirect(withMsg("/#ekle", added.error, true));
      await act("site.add", parsed.site.origin);
      const r = await runSite(monitor, added.row, true);
      return redirect(withMsg(`/site/${parsed.site.id}`, `Site eklendi. ${summarize(r)}`));
    }

    const m = path.match(/^\/site\/([a-z0-9-]{1,60})(?:\/(run|test-mail|pause|resume|reset|delete|edit))?$/);
    if (m) {
      const [, slug, action] = m;
      const row = await getSite(db, orgId, slug);
      if (!row) return errorPage(404, "Site bulunamadı.");
      const here = `/site/${slug}`;
      if (!action && !isPost) {
        await act("site.view", row.site.origin);
        return renderDetail(row, msg, isErr);
      }
      if (!action || !isPost) return errorPage(405, "Desteklenmeyen istek.");
      if (!can.manageSites(role)) return deny(`site ${action}`);
      await act(`site.${action}`, row.site.origin);
      return siteAction(row, action, here);
    }

    const km = path.match(/^\/site\/([a-z0-9-]{1,60})\/anahtar\/(live|test)\/(olustur|yenile|iptal)$/);
    if (km && isPost) {
      const [, slug, mode, op] = km as unknown as [string, string, KeyMode, "olustur" | "yenile" | "iptal"];
      const row = await getSite(db, orgId, slug);
      if (!row) return errorPage(404, "Site bulunamadı.");
      if (!can.manageSites(role)) return deny(`anahtar ${op}`);
      const here = `/site/${slug}`;
      const target = `${row.site.origin} · ${mode}`;
      if (op === "iptal") {
        if (!(await revokeKey(db, row.uuid, mode))) return redirect(withMsg(here, "İptal edilecek anahtar yok.", true));
        await act("key.revoke", target);
        return redirect(withMsg(here, `${mode === "live" ? "Canlı" : "Test"} anahtarı iptal edildi. Bu Site ID ile gelen istekler artık reddedilir.`));
      }
      const r = op === "olustur" ? await createKey(db, row.uuid, mode, cfg.appSecret, sess.userId) : await rotateKey(db, row.uuid, mode, cfg.appSecret);
      if (!r) return redirect(withMsg(here, op === "olustur" ? "Bu modda zaten bir anahtar var; yenileyin ya da önce iptal edin." : "Yenilenecek anahtar yok; önce oluşturun.", true));
      await act(op === "olustur" ? "key.create" : "key.rotate", target);
      // Secret sadece bu cevapta görünür: yönlendirme yok, adres çubuğuna ya da loga düşmez
      return renderDetail(row, op === "olustur" ? "Anahtar oluşturuldu." : "Secret yenilendi; eski secret artık geçersiz.", false, { mode, publicId: r.key.publicId, secret: r.secret });
    }

    if (path === "/ekip" && !isPost) {
      const [members, invites] = await Promise.all([listMembers(db, orgId), can.invite(role) ? listPendingInvites(db, orgId) : Promise.resolve([])]);
      return html(teamPage(ctx, members, invites, sess.userId, msg, isErr));
    }

    if (path === "/ekip/davet" && isPost) {
      if (!can.invite(role)) return deny("davet");
      const fd = await formData(req);
      const email = normalizeEmail(fd.email ?? "");
      const newRole = fd.role as Role;
      if (!validEmail(email)) return redirect(withMsg("/ekip", "Geçerli bir e-posta girin.", true));
      if (!ROLES.includes(newRole) || !can.inviteAs(role, newRole)) return deny(`${newRole} rolüyle davet`);
      if ((await listMembers(db, orgId)).some((x) => x.email === email)) return redirect(withMsg("/ekip", `${email} zaten ekipte.`, true));
      if (!inviteLimit.allow(orgId)) return redirect(withMsg("/ekip", "Bir saatte çok fazla davet gönderildi. Daha sonra tekrar deneyin.", true));
      const { id, token } = await createInvite(db, orgId, email, newRole, sess.userId);
      const link = `${cfg.publicUrl}/davet/${token}`;
      const { subject, html: body } = inviteMail(current.orgName, newRole, sess.email, link);
      if (!deps.mailer) {
        // Sadece yerel geliştirme: SMTP yoksa bağlantı sunucu loguna yazılır, panelde gösterilmez
        console.warn(`[davet] SMTP tanımlı değil; ${email} için davet bağlantısı: ${link}`);
      } else {
        try {
          await deps.mailer([email], subject, body);
        } catch (e) {
          await revokeInvite(db, orgId, id);
          return redirect(withMsg("/ekip", `Davet e-postası gönderilemedi (${(e as Error).message}); davet iptal edildi.`, true));
        }
      }
      await act("invite.sent", email, { role: newRole });
      return redirect(withMsg("/ekip", `${email} adresine davet gönderildi.`));
    }

    const ri = path.match(/^\/ekip\/davet\/([0-9a-f-]{36})\/iptal$/);
    if (ri && isPost) {
      if (!can.invite(role)) return deny("davet iptali");
      const target = (await listPendingInvites(db, orgId)).find((i) => i.id === ri[1]);
      if (!target) return redirect(withMsg("/ekip", "Davet bulunamadı.", true));
      if (!can.inviteAs(role, target.role)) return deny("davet iptali");
      await revokeInvite(db, orgId, target.id);
      await act("invite.revoked", target.email);
      return redirect(withMsg("/ekip", `${target.email} daveti iptal edildi.`));
    }

    const mm = path.match(/^\/ekip\/uye\/([0-9a-f-]{36})\/(rol|cikar)$/);
    if (mm && isPost) {
      const [, uid, op] = mm;
      if (uid === sess.userId) return redirect(withMsg("/ekip", "Kendi rolünüzü değiştiremez ya da kendinizi çıkaramazsınız.", true));
      const targetRole = await getRole(db, uid, orgId);
      if (!targetRole) return redirect(withMsg("/ekip", "Üye bulunamadı.", true));
      const target = await getUser(db, uid);
      const next = op === "rol" ? ((await formData(req)).role as Role) : null;
      if (next !== null && !ROLES.includes(next)) return redirect(withMsg("/ekip", "Geçersiz rol.", true));
      if (!can.changeMember(role, targetRole, next ?? undefined)) return deny(`üye ${op}`);
      const r = await changeMember(db, orgId, uid, next);
      if (!r.ok) return redirect(withMsg("/ekip", r.error, true));
      await act(next ? "member.role" : "member.removed", target?.email, next ? { from: targetRole, to: next } : { role: targetRole });
      return redirect(withMsg("/ekip", next ? `${target?.email}: ${ROLE_LABEL[next]}` : `${target?.email} organizasyondan çıkarıldı.`));
    }

    if (path === "/kayit" && !isPost) {
      if (!can.viewAudit(role)) return deny("erişim kaydı");
      const entries = await listAudit(db, orgId);
      await act("audit.view");
      return html(auditPage(ctx, entries));
    }

    if (path === "/hesap" && !isPost) {
      const user = await getUser(db, sess.userId);
      return html(accountPage(ctx, { recoveryLeft: user?.recovery_codes.length ?? 0 }, msg, isErr));
    }

    if (path === "/hesap/sifre" && isPost) {
      const user = await getUser(db, sess.userId);
      if (!user) return redirect("/login", clearC());
      if (!loginLimit.allow(`pw:${user.id}`)) return redirect(withMsg("/hesap", "Çok fazla deneme. 15 dakika sonra tekrar deneyin.", true));
      const fd = await formData(req);
      if (!(await verifyPassword(fd.current ?? "", user.password_hash))) {
        await registerFailure(db, user.id);
        return redirect(withMsg("/hesap", "Mevcut şifre hatalı.", true));
      }
      const pw = fd.password ?? "";
      const problem = pw !== (fd.password2 ?? "") ? "Yeni şifreler aynı değil" : passwordProblem(pw, user.email);
      if (problem) return redirect(withMsg("/hesap", problem, true));
      await setPassword(db, user.id, await hashPassword(pw));
      await destroyOtherSessions(db, user.id, sess.tokenHash);
      await act("password.changed");
      return redirect(withMsg("/hesap", "Şifreniz değiştirildi; diğer cihazlardaki oturumlar kapatıldı."));
    }

    return errorPage(404, "Sayfa bulunamadı.");

    async function renderDetail(row: SiteRow, m: string | null, err: boolean, revealed?: Revealed): Promise<Response> {
      const [keys, sums] = await Promise.all([listActiveKeys(db, row.uuid), appSummaries(db, [row.uuid], 50)]);
      const app = sums.get(row.uuid);
      const connection = connectionSection({ slug: row.site.id, keys, publicUrl: cfg.publicUrl, manage: can.manageSites(role), revealed, lastEventAt: app?.lastAt ?? null });
      return html(siteDetail(row.site, row.st ?? initialState(), m, err, ctx, { app, connection, reveal: revealed ? revealBox(revealed, cfg.publicUrl, row.site.id) : undefined }));
    }

    async function siteAction(row: SiteRow, action: string, here: string): Promise<Response> {
      switch (action) {
        case "run":
          return redirect(withMsg(here, summarize(await runSite(monitor, row, true))));
        case "test-mail": {
          const r = await sendTestMail(monitor, row.site, `${cfg.publicUrl}${here}`);
          if (!r || typeof r === "string") return redirect(withMsg(here, "Önce uyarı e-postası ekleyin (ya da sunucuda SMTP_PASS tanımlı değil).", true));
          return redirect(withMsg(here, r.ok ? `Test e-postası gönderildi: ${row.site.emails.join(", ")}` : `Gönderilemedi: ${r.error}`, !r.ok));
        }
        case "pause":
        case "resume":
          await updateSite(db, orgId, row.site.id, { paused: action === "pause" });
          return redirect(withMsg(here, action === "pause" ? "Kontroller duraklatıldı." : "Kontroller devam ediyor."));
        case "reset":
          await resetBaseline(db, row);
          return redirect(withMsg(here, "Referans sıfırlandı; bir sonraki kontrolde yeniden öğrenilecek."));
        case "delete":
          await removeSite(db, orgId, row.site.id);
          return redirect(withMsg("/", `${row.site.name} silindi.`));
        case "edit": {
          const fd = await formData(req);
          const parsed = parseSiteInput({ ...fd, url: row.site.origin, ownerConfirmed: "1" }, { allowPrivate: true });
          if (!parsed.ok) return redirect(withMsg(here, parsed.error, true));
          const { name, emails, pages, extraPaths, intervalMin } = parsed.site;
          await updateSite(db, orgId, row.site.id, { name, emails, pages, extraPaths, intervalMin });
          return redirect(withMsg(here, "Ayarlar kaydedildi."));
        }
      }
      return errorPage(405, "Desteklenmeyen istek.");
    }
  }

  return async (req, meta) => {
    try {
      return await handle(req, meta);
    } catch (e) {
      console.error("istek hatası:", e);
      return errorPage(500, "Beklenmeyen bir hata oluştu.");
    }
  };
}

