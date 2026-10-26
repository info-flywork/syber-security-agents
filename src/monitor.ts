/**
 * Site kontrolü — eski Durable Object ajanının (site-agent.ts) Node karşılığı. Kontrol akışı aynı;
 * durum PostgreSQL'de tutulur, eşzamanlı kontrolü veritabanı kilidi (lease) engeller.
 */
import { ALLOWED_SCRIPT_HOSTS } from "./defaults";
import { budgeted, sensitiveList } from "./plan";
import {
  checkSensitive,
  dnsChanges,
  errMsg,
  externalHosts,
  fetchDns,
  fetchPage,
  headerResults,
  hostOf,
  httpsResult,
  redirectResult,
  scriptResult,
  uptimeResult,
} from "./checks";
import { evaluate, mailworthy } from "./incidents";
import { buildAlert, type Notice } from "./alert";
import { claimLease, releaseLease, saveState, type SiteRow } from "./sites";
import type { Db } from "./db";
import type { Mailer } from "./mail";
import type { CheckResult, FetchFn, Incident, SiteConfig, SiteEvent, SiteState } from "./types";

/** Tek kontrolde atılabilecek en fazla istek (sayfalar + hassas dosyalar + DNS). */
const REQUEST_BUDGET = 60;

export interface MonitorDeps {
  db: Db;
  fetchFn: FetchFn;
  mailer: Mailer | null;
  publicUrl: string;
}

export interface RunSummary {
  site: string;
  at: string;
  durationMs: number;
  checks: number;
  failing: number;
  opened: string[];
  resolved: string[];
  notices: string[];
  mail: SiteState["lastMail"] | "gönderilecek bir şey yok" | "alıcı tanımlı değil";
}

export const initialState = (): SiteState => ({
  incidents: {},
  dnsBaseline: null,
  scriptBaseline: {},
  lastRun: null,
  lastDurationMs: 0,
  lastResults: [],
  lastMail: null,
  history: [],
  events: [],
  runs: 0,
});

/** Sırası geldiyse (ya da force) kontrol et. */
export async function runSite(deps: MonitorDeps, row: SiteRow, force = false): Promise<RunSummary | { skipped: string }> {
  const { site } = row;
  if (site.paused && !force) return { skipped: "duraklatıldı" };
  const last = row.st?.lastRun ? Date.parse(row.st.lastRun) : 0;
  if (!force && Date.now() - last < site.intervalMin * 60_000 - 30_000) return { skipped: "sırası gelmedi" };
  const fresh = await claimLease(deps.db, row.uuid);
  if (!fresh) return { skipped: "önceki kontrol sürüyor" };
  try {
    return await doRun(deps, fresh);
  } finally {
    await releaseLease(deps.db, row.uuid);
  }
}

/** Script referansını sıfırla: bir sonraki kontrolde sayfadaki kaynaklar "bilinen" kabul edilir. */
export async function resetBaseline(db: Db, row: SiteRow): Promise<void> {
  if (row.st) await saveState(db, row.uuid, { ...row.st, scriptBaseline: {}, dnsBaseline: null });
}

export async function sendTestMail(deps: MonitorDeps, site: SiteConfig, panelUrl: string): Promise<RunSummary["mail"]> {
  return mail(deps, site, [], [], [], new Date().toISOString(), panelUrl, true);
}

async function doRun(deps: MonitorDeps, row: SiteRow): Promise<RunSummary> {
  const site = row.site;
  const started = Date.now();
  const now = new Date().toISOString();
  const st = row.st ?? initialState();
  const f = budgeted(deps.fetchFn, REQUEST_BUDGET);
  const results: CheckResult[] = [];
  const notices: Notice[] = [];
  const scriptBaseline = { ...st.scriptBaseline };

  // 1) Sayfalar + HTTPS yönlendirmesi
  const [pages, https] = await Promise.all([Promise.all(site.pages.map((p) => fetchPage(f, site.origin, p))), httpsResult(f, site.origin)]);
  for (const p of pages) {
    results.push(uptimeResult(p), redirectResult(p, site.origin));
    if (p.html !== null) {
      const hosts = externalHosts(p.html, site.origin + p.path);
      // İlk görüşte sayfadaki mevcut kaynaklar "bilinen" kabul edilir; sonradan eklenenler uyarı üretir
      if (scriptBaseline[p.path] === undefined) scriptBaseline[p.path] = hosts;
      results.push(scriptResult(p.path, hosts, ALLOWED_SCRIPT_HOSTS, scriptBaseline[p.path]));
    }
  }
  results.push(https);
  if (pages[0]) results.push(...headerResults(pages[0], site.origin));
  const up = pages.some((p) => p.error === null && p.status > 0 && p.status < 500);

  // 2) Hassas dosyalar — site ayaktaysa
  if (up) {
    const list = sensitiveList(site);
    for (let i = 0; i < list.length; i += 8) {
      results.push(...(await Promise.all(list.slice(i, i + 8).map((p) => checkSensitive(f, site.origin, p)))));
    }
  }

  // 3) DNS
  let dnsBaseline = st.dnsBaseline;
  try {
    const dns = await fetchDns(f, hostOf(site.origin), ["A", "NS", "MX"]);
    for (const c of dnsChanges(st.dnsBaseline, dns)) {
      notices.push({
        id: `dns:${c.type}`,
        kind: "dns",
        title: `DNS ${c.type} kaydı değişti`,
        severity: "high",
        detail: `Önce: ${c.before.join(", ") || "yok"} → Şimdi: ${c.after.join(", ") || "yok"}`,
      });
    }
    dnsBaseline = dns;
  } catch (e) {
    console.warn(`[${site.id}] DNS kontrolü yapılamadı:`, errMsg(e));
  }

  const ev = evaluate(st.incidents, results, now);
  const mailOpened = mailworthy(ev.opened);
  const mailResolved = mailworthy(ev.resolved);
  let mailResult: RunSummary["mail"] = "gönderilecek bir şey yok";
  if (mailOpened.length || mailResolved.length || notices.length) {
    mailResult = await mail(deps, site, mailOpened, mailResolved, notices, now, `${deps.publicUrl}/site/${site.id}`);
  }

  const newEvents: SiteEvent[] = [
    ...ev.opened.map((i): SiteEvent => ({ at: now, type: "opened", kind: i.kind, title: i.title, detail: i.detail, severity: i.severity })),
    ...ev.resolved.map((i): SiteEvent => ({ at: now, type: "resolved", kind: i.kind, title: i.title, detail: i.detail, severity: i.severity })),
    ...notices.map((n): SiteEvent => ({ at: now, type: "notice", kind: n.kind, title: n.title, detail: n.detail, severity: n.severity })),
  ];
  const durationMs = Date.now() - started;
  const dayAgo = Date.now() - 24 * 3600_000;
  await saveState(deps.db, row.uuid, {
    incidents: ev.incidents,
    dnsBaseline,
    scriptBaseline,
    lastRun: now,
    lastDurationMs: durationMs,
    lastResults: results,
    lastMail: typeof mailResult === "object" ? mailResult : st.lastMail,
    history: [...st.history.filter((h) => Date.parse(h.at) > dayAgo), { at: now, up, failing: results.filter((r) => !r.ok && r.severity !== "info").length, ms: pages[0]?.ms ?? 0 }].slice(-300),
    events: [...newEvents.reverse(), ...st.events].slice(0, 200),
    runs: st.runs + 1,
  });

  return {
    site: site.id,
    at: now,
    durationMs,
    checks: results.length,
    failing: results.filter((r) => !r.ok).length,
    opened: ev.opened.map((i) => i.title),
    resolved: ev.resolved.map((i) => i.title),
    notices: notices.map((n) => n.title),
    mail: mailResult,
  };
}

async function mail(deps: MonitorDeps, site: SiteConfig, opened: Incident[], resolved: Incident[], notices: Notice[], now: string, panelUrl: string, isTest = false): Promise<RunSummary["mail"]> {
  if (!site.emails.length || !deps.mailer) return "alıcı tanımlı değil";
  const { subject, html } = buildAlert(site, opened, resolved, notices, now, panelUrl, isTest);
  try {
    await deps.mailer(site.emails, subject, html);
    return { ok: true, at: now };
  } catch (e) {
    console.error(`[${site.id}] e-posta gönderilemedi:`, errMsg(e));
    return { ok: false, at: now, error: errMsg(e) };
  }
}
