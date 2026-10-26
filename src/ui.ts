/**
 * Panel HTML'i — sunucu tarafında üretilir, dış kaynak yok. Tüm kullanıcı verisi esc() ile kaçırılır.
 * Görünüm: koyu tema güvenlik operasyon merkezi (SOC) paneli. Kontrol mantığı burada değil; bu dosya sadece çizer.
 */
import { esc, ADVICE } from "./alert";
import { ROLE_LABEL, can, type Role } from "./accounts";
import type { CheckResult, Incident, Kind, RunPoint, Severity, SiteConfig, SiteEvent, SiteState } from "./types";

export type Health = "unknown" | "ok" | "issues" | "down" | "paused";

export function siteHealth(site: SiteConfig, st: SiteState | null): Health {
  if (site.paused) return "paused";
  if (!st || !st.lastRun) return "unknown";
  const open = Object.values(st.incidents).filter((i) => i.alerted && i.severity !== "info");
  if (open.some((i) => i.kind === "uptime")) return "down";
  return open.length ? "issues" : "ok";
}

export function uptimePct(st: SiteState | null): string {
  const h = st?.history ?? [];
  if (!h.length) return "—";
  return `%${((h.filter((p) => p.up).length / h.length) * 100).toFixed(h.length > 20 ? 1 : 0)}`;
}

/**
 * Dış kaynaklardan (ileride Uptime Kuma, Wazuh, yapay zekâ özeti) panele gelecek veriler.
 * Hepsi isteğe bağlı; verilmezse panel ilgili bölümde "bağlı değil" durumunu gösterir.
 */
export type AssetKind = "web" | "ios" | "android" | "api" | "server";
export interface ExternalAsset {
  kind: AssetKind;
  name: string;
  detail?: string;
  status: "ok" | "warn" | "bad" | "unknown";
  /** Verinin geldiği sistem, ör. "Uptime Kuma", "Wazuh" */
  source: string;
}
export interface BlockedIp {
  ip: string;
  reason: string;
  at: string;
  source: string;
  asset?: string;
}
export interface PendingAction {
  title: string;
  detail: string;
  severity: Severity;
  source: string;
  href?: string;
}
export interface ExternalFeeds {
  assets?: ExternalAsset[];
  blockedIps?: BlockedIp[];
  actions?: PendingAction[];
  aiSummary?: { text: string; at: string; model?: string };
}

type Row = { site: SiteConfig; st: SiteState | null };

/** Oturumdaki kullanıcı ve aktif organizasyon — menü, üst çubuk ve yetkiye göre düğmeler için. */
export interface PanelCtx {
  email: string;
  role: Role;
  orgId: string;
  orgName: string;
  orgs: { id: string; name: string }[];
  /** Menüdeki site listesi (detay sayfasında tüm siteler görünsün diye) */
  sites?: { id: string; name: string; health: Health }[];
}

const DEFAULT_CTX: PanelCtx = { email: "", role: "owner", orgId: "", orgName: "", orgs: [] };

const HEALTH: Record<Health, [string, string]> = {
  unknown: ["Henüz kontrol edilmedi", "muted"],
  ok: ["Sağlıklı", "ok"],
  issues: ["Sorun var", "warn"],
  down: ["Erişilemiyor", "bad"],
  paused: ["Duraklatıldı", "muted"],
};

const KIND_LABEL: Record<Kind, string> = {
  uptime: "Erişim",
  https: "HTTPS",
  redirect: "Yönlendirme",
  script: "Dış kod",
  exposed: "Hassas dosyalar",
  headers: "Güvenlik başlıkları",
  dns: "DNS",
};

const SEV: Record<Severity, { label: string; cls: string; weight: number; rank: number }> = {
  critical: { label: "Kritik", cls: "crit", weight: 30, rank: 0 },
  high: { label: "Yüksek", cls: "high", weight: 12, rank: 1 },
  info: { label: "Öneri", cls: "info", weight: 2, rank: 2 },
};

const ASSET_LABEL: Record<AssetKind, [string, string]> = {
  web: ["WEB", "Web sitesi"],
  ios: ["iOS", "iOS uygulaması"],
  android: ["AND", "Android uygulaması"],
  api: ["API", "API uç noktası"],
  server: ["SRV", "Sunucu"],
};

const TZ = "Europe/Istanbul";
export const fmt = (iso: string | null) =>
  iso ? new Date(iso).toLocaleString("tr-TR", { timeZone: TZ, day: "2-digit", month: "2-digit", hour: "2-digit", minute: "2-digit" }) : "—";
const clock = (ms: number) => new Date(ms).toLocaleTimeString("tr-TR", { timeZone: TZ, hour: "2-digit", minute: "2-digit" });

function ago(iso: string | null, now: number): string {
  if (!iso) return "—";
  const m = Math.round((now - Date.parse(iso)) / 60000);
  if (m < 1) return "az önce";
  if (m < 60) return `${m} dk önce`;
  if (m < 24 * 60) return `${Math.floor(m / 60)} sa önce`;
  return fmt(iso);
}

/** Bağlantılarda sadece panel içi yollar ya da http(s) adresleri. */
const safeHref = (h: string | undefined) => (h && (/^\/(?!\/)/.test(h) || /^https?:\/\//i.test(h)) ? esc(h) : "");

const openIncidents = (st: SiteState | null): Incident[] => (st ? Object.values(st.incidents).filter((i) => i.alerted) : []);
const bySeverity = (a: { severity: Severity }, b: { severity: Severity }) => SEV[a.severity].rank - SEV[b.severity].rank;

/** 0–100 arası risk puanı: açık bulguların ağırlıkları toplanır (duraklatılmış siteler hariç). */
function riskScore(rows: Row[]): number | null {
  const active = rows.filter((r) => !r.site.paused && r.st?.lastRun);
  if (!active.length) return null;
  const sum = active.flatMap((r) => openIncidents(r.st)).reduce((s, i) => s + SEV[i.severity].weight, 0);
  return Math.min(100, sum);
}

function riskLevel(score: number | null): [string, string] {
  if (score === null) return ["Veri yok", "muted"];
  if (score >= 80) return ["Kritik", "bad"];
  if (score >= 50) return ["Yüksek", "bad"];
  if (score >= 20) return ["Orta", "warn"];
  return ["Düşük", "ok"];
}

const CSS = `
:root{color-scheme:light;--bg:#f3f5f9;--panel:#fff;--panel2:#f7f9fc;--hover:#eef3f9;--line:#e2e7ef;--line2:#cfd7e3;--line3:#aab6c7;--ink:#0f172a;--muted:#5b6678;--accent:#0284c7;--accentbg:rgba(2,132,199,.09);--onaccent:#fff;--barbg:rgba(243,245,249,.9);--ok:#059669;--okbg:rgba(5,150,105,.1);--warn:#b45309;--warnbg:rgba(217,119,6,.12);--bad:#e11d48;--badbg:rgba(225,29,72,.09);--mutedbg:rgba(91,102,120,.1);--crit:#e11d48;--high:#b45309;--info:#64748b;--mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;--barh:56px}
@media (prefers-color-scheme:dark){:root:not([data-theme=light]){color-scheme:dark;--bg:#080b12;--panel:#0e131d;--panel2:#121927;--hover:#151d2c;--line:#1c2433;--line2:#283244;--line3:#3a475e;--ink:#e6ebf2;--muted:#8592a6;--accent:#38bdf8;--accentbg:rgba(56,189,248,.12);--onaccent:#04121c;--barbg:rgba(8,11,18,.9);--ok:#34d399;--okbg:rgba(52,211,153,.12);--warn:#fbbf24;--warnbg:rgba(251,191,36,.12);--bad:#fb7185;--badbg:rgba(251,113,133,.13);--mutedbg:rgba(133,146,166,.12);--crit:#fb7185;--high:#fbbf24;--info:#94a3b8}}
:root[data-theme=dark]{color-scheme:dark;--bg:#080b12;--panel:#0e131d;--panel2:#121927;--hover:#151d2c;--line:#1c2433;--line2:#283244;--line3:#3a475e;--ink:#e6ebf2;--muted:#8592a6;--accent:#38bdf8;--accentbg:rgba(56,189,248,.12);--onaccent:#04121c;--barbg:rgba(8,11,18,.9);--ok:#34d399;--okbg:rgba(52,211,153,.12);--warn:#fbbf24;--warnbg:rgba(251,191,36,.12);--bad:#fb7185;--badbg:rgba(251,113,133,.13);--mutedbg:rgba(133,146,166,.12);--crit:#fb7185;--high:#fbbf24;--info:#94a3b8}
*{box-sizing:border-box}html{background:var(--bg)}body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif;-webkit-font-smoothing:antialiased}
a{color:var(--accent);text-decoration:none}a:hover{text-decoration:underline}
.bar{position:sticky;top:0;z-index:5;background:var(--barbg);backdrop-filter:blur(8px);border-bottom:1px solid var(--line)}
.bar-in{height:var(--barh);padding:0 20px;display:flex;align-items:center;gap:16px}
.brand{display:flex;align-items:center;gap:10px;color:var(--ink);font-weight:700;letter-spacing:.02em}.brand:hover{text-decoration:none}
.brand small{display:block;font-weight:500;color:var(--muted);font-size:11px;letter-spacing:.08em;text-transform:uppercase}
.logo{width:30px;height:30px;border-radius:8px;display:grid;place-items:center;background:var(--accentbg);border:1px solid var(--line2);color:var(--accent)}
.bar .sp{flex:1}
.who{display:flex;flex-direction:column;align-items:flex-end;line-height:1.25;font-size:13px;max-width:260px;min-width:0}.who b,.who small{max-width:100%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.who small{color:var(--muted);font-size:11.5px}
.orgsel{padding:8px 10px 2px}.orgsel select{font-size:13px;padding:6px 8px}
button.theme{padding:7px 9px;line-height:0;color:var(--muted)}button.theme:hover{color:var(--ink)}.i-moon{display:none}
@media (prefers-color-scheme:dark){:root:not([data-theme=light]) .i-sun{display:none}:root:not([data-theme=light]) .i-moon{display:inline}}
:root[data-theme=dark] .i-sun{display:none}:root[data-theme=dark] .i-moon{display:inline}.live{display:flex;align-items:center;gap:8px;color:var(--muted);font:12px var(--mono)}
.dot{display:inline-block;flex:none;width:8px;height:8px;border-radius:50%;background:var(--ok);box-shadow:0 0 0 3px var(--okbg)}.dot.ok{background:var(--ok)}.dot.warn{background:var(--warn);box-shadow:0 0 0 3px var(--warnbg)}.dot.bad{background:var(--bad);box-shadow:0 0 0 3px var(--badbg)}.dot.muted{background:var(--muted);box-shadow:0 0 0 3px var(--mutedbg)}
main{padding:22px 24px 64px;max-width:1360px;width:100%;min-width:0}
.shell{display:grid;grid-template-columns:236px minmax(0,1fr);align-items:start}
.side{position:sticky;top:var(--barh);height:calc(100vh - var(--barh));overflow:auto;border-right:1px solid var(--line);background:var(--panel);padding:10px 10px 24px}
.side .sg{font-size:10.5px;font-weight:600;letter-spacing:.1em;text-transform:uppercase;color:var(--muted);padding:16px 10px 6px}
.side a,.side .it{display:flex;align-items:center;gap:10px;padding:7px 10px;border-radius:8px;color:var(--ink);font-size:13.5px;min-width:0}
.side a:hover{background:var(--hover);text-decoration:none}.side a.on{background:var(--accentbg);color:var(--accent);font-weight:600}
.side svg{flex:none;color:var(--muted)}.side a.on svg{color:var(--accent)}.side .it{color:var(--muted)}
.side .nm{flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.side .cnt{margin-left:auto;font:11.5px var(--mono);color:var(--muted);background:var(--panel2);border:1px solid var(--line);border-radius:999px;padding:0 7px}
.side .cnt.crit{color:var(--crit);background:var(--badbg);border-color:transparent}.side .cnt.high{color:var(--high);background:var(--warnbg);border-color:transparent}
.vh{display:flex;align-items:flex-end;justify-content:space-between;gap:12px;flex-wrap:wrap;margin-bottom:16px}.vh p{margin:3px 0 0;color:var(--muted);font-size:13px}
.g-top>.kpis{grid-auto-rows:1fr}a.kpi{display:flex;flex-direction:column;justify-content:center;color:inherit}a.kpi:hover{text-decoration:none;border-color:var(--line3)}
.more{display:block;margin-top:12px;font-size:13px}
[hidden]{display:none!important}
@media (max-width:900px){.shell{grid-template-columns:minmax(0,1fr)}.side{z-index:4;height:auto;display:flex;gap:4px;overflow-x:auto;padding:8px 12px;border-right:0;border-bottom:1px solid var(--line)}.side .sg,.side .grp-x{display:none}.side a{flex:none;white-space:nowrap}}
h1,h2,h3{margin:0}h1{font-size:20px}h2{font-size:12px;font-weight:600;letter-spacing:.08em;text-transform:uppercase;color:var(--muted)}
.card{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:16px;min-width:0}
.card>header{display:flex;align-items:center;justify-content:space-between;gap:10px;margin:-2px 0 14px}
.count{font:12px var(--mono);color:var(--muted)}
.grid{display:grid;gap:16px}.stack{display:grid;gap:16px;align-content:start;min-width:0}
.g-top{grid-template-columns:minmax(280px,360px) minmax(0,1fr)}
.g-main{grid-template-columns:minmax(0,1.6fr) minmax(300px,1fr)}
.sec{margin-top:16px}
@media (max-width:1000px){.g-top,.g-main{grid-template-columns:minmax(0,1fr)}}
.risk{display:flex;align-items:center;gap:18px}
.risk .num{font:700 40px/1 var(--mono)}.risk .of{color:var(--muted);font:13px var(--mono)}
.prot{margin-top:14px;padding-top:14px;border-top:1px solid var(--line);display:grid;gap:8px}
.prot .row{display:flex;justify-content:space-between;align-items:center;gap:10px;font-size:13px}.prot .row>span:first-child{color:var(--muted)}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px}
.kpi{background:var(--panel2);border:1px solid var(--line);border-radius:10px;padding:12px 14px}
.kpi .l{font-size:11px;letter-spacing:.06em;text-transform:uppercase;color:var(--muted)}.kpi .v{font:600 26px/1.25 var(--mono);margin-top:4px}.kpi .s{font-size:12px;color:var(--muted)}
.v.crit{color:var(--crit)}.v.high{color:var(--high)}.v.ok{color:var(--ok);background:none}
.tag{display:inline-flex;align-items:center;gap:6px;padding:2px 8px;border-radius:6px;font-size:11.5px;font-weight:600;white-space:nowrap;border:1px solid transparent}
.ok{background:var(--okbg);color:var(--ok)}.warn{background:var(--warnbg);color:var(--warn)}.bad{background:var(--badbg);color:var(--bad)}.muted{background:var(--mutedbg);color:var(--muted)}
.sev{font-family:var(--mono);letter-spacing:.04em;text-transform:uppercase;font-size:10.5px}
.sev.crit{background:var(--badbg);color:var(--crit);border-color:color-mix(in srgb,var(--crit) 35%,transparent)}.sev.high{background:var(--warnbg);color:var(--high);border-color:color-mix(in srgb,var(--high) 30%,transparent)}.sev.info{background:var(--mutedbg);color:var(--info)}
.chip{display:inline-block;padding:1px 7px;border-radius:5px;background:var(--panel2);border:1px solid var(--line2);color:var(--muted);font-size:11.5px;white-space:nowrap}
.ty{font:600 10.5px var(--mono);letter-spacing:.06em;color:var(--accent);background:var(--accentbg);border-radius:5px;padding:2px 6px}
.assets{display:grid;grid-template-columns:repeat(auto-fill,minmax(230px,1fr));gap:12px}
.asset{display:block;background:var(--panel2);border:1px solid var(--line);border-radius:10px;padding:12px 14px 12px 16px;color:var(--ink);position:relative;overflow:hidden}
a.asset:hover{text-decoration:none;border-color:var(--line2);background:var(--hover)}
.asset::before{content:"";position:absolute;left:0;top:0;bottom:0;width:3px;background:var(--line2)}
.asset.s-ok::before{background:var(--ok)}.asset.s-warn::before{background:var(--warn)}.asset.s-bad::before{background:var(--bad)}
.asset .top{display:flex;align-items:center;gap:8px}
.asset .nm{font-weight:600;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;flex:1}
.asset .or{font:12px var(--mono);color:var(--muted);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;margin:2px 0 10px}
.asset .ft{display:flex;align-items:flex-end;justify-content:space-between;gap:8px;font-size:12px;color:var(--muted)}.asset .ft b{color:var(--ink);font-family:var(--mono);font-weight:600}
.asset.empty{border-style:dashed;background:transparent;color:var(--muted)}.asset.empty::before{display:none}.asset.empty .ty{color:var(--muted);background:var(--mutedbg)}
.find{list-style:none;margin:0;padding:0}.find li{padding:12px 0;border-top:1px solid var(--line)}.find li:first-child{border-top:0;padding-top:0}
.find .h{display:flex;align-items:center;gap:8px;flex-wrap:wrap}.find .t{font-weight:600}
.find .d{color:var(--muted);font-size:13px;margin-top:4px;word-break:break-word}
.fix{margin-top:8px;padding:8px 10px;border-radius:8px;background:var(--panel2);border:1px solid var(--line);font-size:13px}.fix b{color:var(--accent);font-weight:600;font-size:11px;letter-spacing:.06em;text-transform:uppercase;margin-right:8px}
.feed{list-style:none;margin:0;padding:0}.feed li{display:grid;grid-template-columns:44px 12px minmax(0,1fr);gap:8px;padding:7px 0}
.feed .tm{font:12px var(--mono);color:var(--muted);text-align:right;padding-top:1px}
.feed .mk{width:9px;height:9px;border-radius:50%;margin-top:6px;background:var(--line2)}.feed .mk.ok{background:var(--ok)}.feed .mk.bad{background:var(--bad)}.feed .mk.warn{background:var(--warn)}.feed .mk.muted{background:var(--info)}
.feed .tx{font-size:13px}.feed .tx .sm{display:block;color:var(--muted);font-size:12px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.scroll{max-height:440px;overflow:auto;margin-right:-8px;padding-right:8px}
.chart{width:100%;height:auto;display:block}.chart text{fill:var(--muted);font:10px var(--mono)}.chart .gl{stroke:var(--line);stroke-width:1}
.legend{display:flex;gap:14px;flex-wrap:wrap;font-size:12px;color:var(--muted);margin-top:8px}.legend i{display:inline-block;width:10px;height:10px;border-radius:2px;margin-right:5px;vertical-align:-1px}
.empty-state{border:1px dashed var(--line2);border-radius:10px;padding:16px;color:var(--muted);font-size:13px;text-align:center}
.empty-state b{display:block;color:var(--ink);font-weight:600;margin-bottom:2px}
.ai{background:linear-gradient(180deg,var(--accentbg),transparent 70%),var(--panel)}
.ai p{margin:0 0 8px}.ai ul{margin:0;padding-left:18px}.ai li{margin:3px 0}.ai .src{margin-top:10px;font-size:11.5px;color:var(--muted)}
.list{list-style:none;margin:0;padding:0}.list li{padding:9px 0;border-top:1px solid var(--line);display:flex;gap:10px;align-items:flex-start}.list li:first-child{border-top:0;padding-top:0}
.list .grow{flex:1;min-width:0}.list .sm{color:var(--muted);font-size:12px}
.ip{font:13px var(--mono)}
table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:8px;border-bottom:1px solid var(--line);font-size:13px;vertical-align:top}th{font-size:11px;color:var(--muted);font-weight:600;letter-spacing:.06em;text-transform:uppercase}tr:last-child td{border-bottom:0}
form.inline{display:inline}
button,.btn{font:inherit;font-size:13px;cursor:pointer;border:1px solid var(--line2);background:var(--panel2);color:var(--ink);padding:7px 12px;border-radius:8px;display:inline-block;white-space:nowrap}
button:hover,.btn:hover{border-color:var(--line3);text-decoration:none}
button.primary{background:var(--accent);border-color:var(--accent);color:var(--onaccent);font-weight:600}button.danger{color:var(--bad)}
label{display:block;font-weight:600;font-size:13px;margin:12px 0 5px}label small{font-weight:400;color:var(--muted)}
input[type=text],input[type=password],input[type=url],textarea,select{width:100%;font:inherit;padding:8px 10px;border:1px solid var(--line2);border-radius:8px;background:var(--bg);color:var(--ink)}
input:focus,textarea:focus,select:focus{outline:2px solid color-mix(in srgb,var(--accent) 50%,transparent);outline-offset:0;border-color:var(--accent)}
textarea{min-height:64px}.check{display:flex;gap:8px;align-items:flex-start;font-weight:400}.check input{margin-top:4px}
.cols{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:12px}
details.fold>summary{cursor:pointer;list-style:none;display:flex;align-items:center;justify-content:space-between;gap:10px}details.fold>summary::-webkit-details-marker{display:none}
details.fold>summary .tog{font-size:13px;color:var(--accent)}details.fold[open] .tog-c,details.fold:not([open]) .tog-o{display:none}
.flash{padding:10px 14px;border-radius:10px;margin-bottom:16px;border:1px solid color-mix(in srgb,var(--accent) 35%,transparent);background:var(--accentbg)}.flash.err{border-color:color-mix(in srgb,var(--bad) 40%,transparent);background:var(--badbg);color:var(--bad)}
.kv{display:grid;grid-template-columns:max-content 1fr;gap:6px 16px;margin:0}.kv dt{color:var(--muted)}.kv dd{margin:0;word-break:break-word}
.actions{display:flex;gap:8px;flex-wrap:wrap}code{font:12.5px var(--mono);word-break:break-all}.small{font-size:12.5px;color:var(--muted)}
.res{display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:12px}.res .card{background:var(--panel2)}
.res .line{font-size:12.5px;color:var(--muted);margin-top:3px;word-break:break-word}
.crumb{font-size:13px;color:var(--muted);margin-bottom:12px}
.center{max-width:420px;margin:8vh auto 0}
@media (max-width:640px){.bar-in,main{padding-left:16px;padding-right:16px}.brand small{display:none}.hide-sm{display:none}.risk .num{font-size:34px}.kpi .v{font-size:22px}}
`;

const LOGO = `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 3l8 3v6c0 4.5-3.4 8.3-8 9-4.6-.7-8-4.5-8-9V6z"/><circle cx="12" cy="11" r="2.5"/></svg>`;

// Tema: varsayılan sistem tercihi; düğmeyle seçilen tema bu tarayıcıda hatırlanır.
const THEME_INIT = `(function(){try{var t=localStorage.getItem('sg-theme');if(t==='light'||t==='dark')document.documentElement.dataset.theme=t}catch(e){}})();
function sgTheme(){var r=document.documentElement,cur=r.dataset.theme||(matchMedia('(prefers-color-scheme: dark)').matches?'dark':'light'),n=cur==='dark'?'light':'dark';r.dataset.theme=n;try{localStorage.setItem('sg-theme',n)}catch(e){}}`;

const THEME_ICON = `<svg class="i-sun" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/></svg><svg class="i-moon" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z"/></svg>`;

// Sol menü: aynı sayfadaki bölümler (data-view) adres çubuğundaki #bölüm'e göre gösterilir.
const NAV_SCRIPT = `(function(){function show(){var vs=document.querySelectorAll('[data-view]');if(!vs.length)return;var h=location.hash.slice(1);if(!document.querySelector('[data-view="'+h+'"]'))h='genel';vs.forEach(function(v){v.hidden=v.dataset.view!==h});document.querySelectorAll('[data-nav]').forEach(function(a){a.classList.toggle('on',a.dataset.nav===h)});window.scrollTo(0,0)}addEventListener('hashchange',show);show()})();`;

export function layout(title: string, body: string, opts: { authed?: boolean; status?: [string, string]; script?: string; side?: string; account?: PanelCtx } = {}): string {
  const [stText, stCls] = opts.status ?? ["", ""];
  return `<!doctype html><html lang="tr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow"><meta name="color-scheme" content="light dark"><title>${esc(title)} — Site Gözcü</title><style>${CSS}</style><script>${THEME_INIT}</script></head><body>
<div class="bar"><div class="bar-in"><a class="brand" href="/"><span class="logo">${LOGO}</span><span>Site Gözcü<small>Güvenlik operasyon merkezi</small></span></a><span class="sp"></span>
${stText ? `<span class="live hide-sm"><span class="dot ${stCls}"></span>${esc(stText)}</span>` : ""}
${opts.account?.email ? `<span class="who hide-sm"><b>${esc(opts.account.orgName)}</b><small>${esc(opts.account.email)} · ${ROLE_LABEL[opts.account.role]}</small></span>` : ""}
<button type="button" class="theme" onclick="sgTheme()" title="Açık / koyu tema" aria-label="Açık / koyu tema">${THEME_ICON}</button>
${opts.authed ? `<form class="inline" method="post" action="/logout"><button>Çıkış</button></form>` : ""}</div></div>
${opts.side ? `<div class="shell">${opts.side}<main>${body}</main></div><script>${NAV_SCRIPT}</script>` : `<main>${body}</main>`}${opts.script ? `<script>${opts.script}</script>` : ""}</body></html>`;
}

export function flash(msg: string | null, isErr = false): string {
  return msg ? `<div class="flash${isErr ? " err" : ""}" role="status">${esc(msg)}</div>` : "";
}

export function loginPage(error: string | null, email = "", next = ""): string {
  const body = `<div class="center">${flash(error, true)}<div class="card"><header><h2>Panel girişi</h2></header>
<form method="post" action="/login">${next ? `<input type="hidden" name="next" value="${esc(next)}">` : ""}
<label for="e" style="margin-top:0">E-posta</label><input id="e" type="text" inputmode="email" name="email" value="${esc(email)}" autocomplete="username" required${email ? "" : " autofocus"}>
<label for="p">Şifre</label><input id="p" type="password" name="password" autocomplete="current-password" required${email ? " autofocus" : ""}>
<p style="margin:16px 0 0"><button class="primary">Devam</button></p></form></div>
<p class="small" style="text-align:center">Hesabınız yoksa organizasyonunuzun sahibinden davet isteyin.</p></div>`;
  return layout("Giriş", body);
}

const toggle = (closed: string, open = "Kapat") => `<span class="tog"><span class="tog-c">${closed}</span><span class="tog-o">${open}</span></span>`;

export function addSiteForm(): string {
  return `<section class="card" style="max-width:920px"><form method="post" action="/sites">
<div class="cols"><div><label for="url">Site adresi</label><input id="url" type="text" name="url" placeholder="https://ornek.com" required></div>
<div><label for="name">Görünen ad <small>(isteğe bağlı)</small></label><input id="name" type="text" name="name" placeholder="Örnek Şirket"></div></div>
<label for="emails">Uyarı e-postaları <small>(virgül ya da satırla ayırın)</small></label><textarea id="emails" name="emails" placeholder="guvenlik@ornek.com"></textarea>
<div class="cols"><div><label for="pages">Ek kontrol sayfaları <small>(ana sayfa her zaman; en fazla 2 ek)</small></label><textarea id="pages" name="pages" placeholder="/giris&#10;/iletisim"></textarea></div>
<div><label for="extra">Siteye özel hassas dosyalar <small>(isteğe bağlı, .php olmaz)</small></label><textarea id="extra" name="extraPaths" placeholder="/yedek-2026.zip"></textarea></div></div>
<label for="iv">Kontrol sıklığı</label><select id="iv" name="intervalMin"><option value="5">5 dakikada bir</option><option value="15" selected>15 dakikada bir</option><option value="60">Saatte bir</option></select>
<label class="check"><input type="checkbox" name="ownerConfirmed" value="1" required> <span>Bu sitenin sahibiyim ya da sahibinden izleme izni aldım. <span class="small">Gözcü siteye düzenli istek atar ve yaygın hassas dosya adlarını dener.</span></span></label>
<p style="margin:16px 0 0"><button class="primary">Ekle ve kontrol et</button></p></form></section>`;
}

// ——— Bileşenler ———

function gauge(score: number | null): string {
  const [, cls] = riskLevel(score);
  const color = cls === "bad" ? "var(--bad)" : cls === "warn" ? "var(--warn)" : cls === "ok" ? "var(--ok)" : "var(--muted)";
  const r = 44;
  const c = 2 * Math.PI * r;
  const filled = score === null ? 0 : Math.max(0.02, score / 100) * c;
  return `<svg width="108" height="108" viewBox="0 0 108 108" role="img" aria-label="Risk puanı ${score ?? "yok"}"><circle cx="54" cy="54" r="${r}" fill="none" stroke="var(--line)" stroke-width="10"/>
<circle cx="54" cy="54" r="${r}" fill="none" stroke="${color}" stroke-width="10" stroke-linecap="round" stroke-dasharray="${filled.toFixed(1)} ${c.toFixed(1)}" transform="rotate(-90 54 54)"/></svg>`;
}

/** Son 24 saat: saatlik erişilebilirlik çubukları + ortalama yanıt süresi çizgisi. */
function accessChart(points: RunPoint[], now: number): string {
  const W = 720, H = 190, L = 36, R = 48, T = 12, B = 26;
  const pw = W - L - R, ph = H - T - B;
  const start = now - 24 * 3600_000;
  const buckets = Array.from({ length: 24 }, () => ({ n: 0, up: 0, ms: 0 }));
  for (const p of points) {
    const i = Math.floor((Date.parse(p.at) - start) / 3600_000);
    if (i < 0 || i > 23) continue;
    buckets[i].n++;
    if (p.up) {
      buckets[i].up++;
      buckets[i].ms += p.ms;
    }
  }
  const msTop = Math.ceil(Math.max(500, ...buckets.map((b) => (b.up ? b.ms / b.up : 0))) / 500) * 500;
  const slot = pw / 24;
  const bw = Math.max(4, slot - 4);
  let bars = "";
  const line: [number, number][] = [];
  buckets.forEach((b, i) => {
    const x = L + i * slot + (slot - bw) / 2;
    const from = clock(start + i * 3600_000);
    if (!b.n) {
      bars += `<rect x="${x.toFixed(1)}" y="${T + ph - 2}" width="${bw.toFixed(1)}" height="2" fill="var(--line2)"><title>${from} · kontrol yok</title></rect>`;
      return;
    }
    const pct = (b.up / b.n) * 100;
    const h = Math.max(2, (pct / 100) * ph);
    const fill = pct >= 99.9 ? "var(--ok)" : pct >= 95 ? "var(--warn)" : "var(--bad)";
    const avg = b.up ? Math.round(b.ms / b.up) : null;
    bars += `<rect x="${x.toFixed(1)}" y="${(T + ph - h).toFixed(1)}" width="${bw.toFixed(1)}" height="${h.toFixed(1)}" rx="2" fill="${fill}" fill-opacity=".5"><title>${from} · %${pct.toFixed(1)} erişilebilir · ${b.n} kontrol${avg !== null ? ` · ort. ${avg} ms` : ""}</title></rect>`;
    if (avg !== null) line.push([L + i * slot + slot / 2, T + ph - (avg / msTop) * ph]);
  });
  let grid = "";
  for (const v of [0, 50, 100]) {
    const y = T + ph - (v / 100) * ph;
    grid += `<line class="gl" x1="${L}" x2="${W - R}" y1="${y}" y2="${y}"/><text x="${L - 6}" y="${y + 3}" text-anchor="end">%${v}</text><text x="${W - R + 6}" y="${y + 3}">${Math.round((v / 100) * msTop)}ms</text>`;
  }
  for (const i of [0, 6, 12, 18]) grid += `<text x="${L + i * slot}" y="${H - 8}">${clock(start + i * 3600_000)}</text>`;
  grid += `<text x="${W - R}" y="${H - 8}" text-anchor="end">şimdi</text>`;
  const pts = line.map(([x, y]) => `${x.toFixed(1)},${y.toFixed(1)}`);
  const poly = pts.length > 1 ? `<polyline points="${pts.join(" ")}" fill="none" stroke="var(--accent)" stroke-width="1.8" stroke-linejoin="round"/>` : "";
  const dots = line.map(([x, y]) => `<circle cx="${x.toFixed(1)}" cy="${y.toFixed(1)}" r="2.2" fill="var(--accent)"/>`).join("");
  return `<svg class="chart" viewBox="0 0 ${W} ${H}" role="img" aria-label="Son 24 saatlik erişilebilirlik ve yanıt süresi">${grid}${bars}${poly}${dots}</svg>
<div class="legend"><span><i style="background:var(--ok);opacity:.7"></i>Erişilebilir (saatlik %)</span><span><i style="background:var(--warn);opacity:.7"></i>Kısmi kesinti</span><span><i style="background:var(--bad);opacity:.7"></i>Ciddi kesinti</span><span><i style="background:var(--accent)"></i>Ort. yanıt süresi</span></div>`;
}

function sparkline(points: RunPoint[]): string {
  const p = points.slice(-30);
  if (p.length < 2) return "";
  const max = Math.max(1, ...p.map((x) => x.ms));
  const w = 90, h = 26;
  const pts = p.map((x, i) => `${((i / (p.length - 1)) * w).toFixed(1)},${(h - 2 - (x.up ? (x.ms / max) * (h - 4) : 0)).toFixed(1)}`).join(" ");
  const down = p.some((x) => !x.up);
  return `<svg width="${w}" height="${h}" viewBox="0 0 ${w} ${h}" aria-hidden="true" style="flex:none"><polyline points="${pts}" fill="none" stroke="${down ? "var(--bad)" : "var(--accent)"}" stroke-width="1.5" stroke-linejoin="round"/></svg>`;
}

function findingItem(i: Incident, site: SiteConfig | null, now: number): string {
  const s = SEV[i.severity];
  return `<li><div class="h"><span class="tag sev ${s.cls}">${s.label}</span><span class="t">${esc(i.title)}</span></div>
<div class="h" style="margin-top:5px">${site ? `<a class="chip" href="/site/${esc(site.id)}">${esc(site.name)}</a>` : ""}<span class="chip">${KIND_LABEL[i.kind]}</span><span class="small">${ago(i.since, now)} açıldı · ${i.fails} ardışık tespit</span></div>
<div class="d">${esc(i.detail)}</div><div class="fix"><b>Düzeltme</b>${esc(ADVICE[i.kind])}</div></li>`;
}

const EVENT_STYLE: Record<SiteEvent["type"], [string, string]> = { opened: ["Açıldı", "bad"], resolved: ["Düzeldi", "ok"], notice: ["Bildirim", "warn"] };

function eventItem(e: SiteEvent, site: SiteConfig | null, now: number): string {
  const [label, cls] = EVENT_STYLE[e.type];
  const mk = e.type === "opened" && e.severity === "info" ? "muted" : cls;
  const t = Date.parse(e.at);
  const stamp = now - t < 20 * 3600_000 ? clock(t) : new Date(t).toLocaleDateString("tr-TR", { timeZone: TZ, day: "2-digit", month: "2-digit" });
  return `<li><span class="tm" title="${esc(fmt(e.at))}">${stamp}</span><span class="mk ${mk}"></span>
<span class="tx"><b>${esc(e.title)}</b> <span class="tag ${cls}" style="font-size:10.5px;padding:0 6px">${label}</span><span class="sm" title="${esc(e.detail)}">${site ? `${esc(site.name)} · ` : ""}${KIND_LABEL[e.kind]} · ${esc(e.detail)}</span></span></li>`;
}

export function emptyState(title: string, text: string): string {
  return `<div class="empty-state"><b>${esc(title)}</b>${esc(text)}</div>`;
}

/** Bekleyen insan aksiyonları: mevcut verilerden türetilir; dış kaynaklardan gelenler eklenir. */
function pendingActions(rows: Row[], extra: PendingAction[]): PendingAction[] {
  const out: PendingAction[] = [];
  for (const { site, st } of rows) {
    const href = `/site/${site.id}`;
    const scripts = openIncidents(st).filter((i) => i.kind === "script");
    if (scripts.length)
      out.push({ title: "Yeni dış kodu onayla ya da kaldır", detail: `${site.name}: ${scripts.length} yeni dış kaynak. Bilerek eklendiyse "Script referansını sıfırla" ile onaylayın.`, severity: "high", source: "Gözcü", href });
    if (!site.emails.length) out.push({ title: "Uyarı alıcısı tanımla", detail: `${site.name} için uyarı e-postası yok; sorunlar kimseye bildirilmiyor.`, severity: "high", source: "Gözcü", href });
    if (st?.lastMail && !st.lastMail.ok) out.push({ title: "E-posta gönderimini düzelt", detail: `${site.name}: son uyarı gönderilemedi (${st.lastMail.error ?? "bilinmeyen hata"}).`, severity: "high", source: "Gözcü", href });
    if (site.paused) out.push({ title: "Duraklatılmış izlemeyi gözden geçir", detail: `${site.name} şu an izlenmiyor.`, severity: "info", source: "Gözcü", href });
  }
  return [...out, ...extra].sort(bySeverity);
}

/** Yapay zekâ özeti bağlanana kadar mevcut verilerden kural tabanlı günlük özet. */
function ruleSummary(rows: Row[], now: number): string {
  if (!rows.length) return `<p>Henüz izlenen varlık yok. İlk web sitesini ekleyince günlük özet burada oluşur.</p>`;
  const day = now - 24 * 3600_000;
  const events = rows.flatMap(({ st }) => (st?.events ?? []).filter((e) => Date.parse(e.at) >= day));
  const opened = events.filter((e) => e.type === "opened").length;
  const resolved = events.filter((e) => e.type === "resolved").length;
  const open = rows.flatMap(({ site, st }) => openIncidents(st).map((i) => ({ i, site })));
  const crit = open.filter((x) => x.i.severity === "critical");
  const down = rows.filter((r) => siteHealth(r.site, r.st) === "down");
  const hist = rows.flatMap((r) => (r.st?.history ?? []).filter((p) => Date.parse(p.at) >= day));
  const bullets = [`Son 24 saatte <b>${opened}</b> yeni bulgu açıldı, <b>${resolved}</b> bulgu düzeldi.`];
  if (hist.length) bullets.push(`Toplam erişilebilirlik <b>%${((hist.filter((p) => p.up).length / hist.length) * 100).toFixed(1)}</b> (${hist.length} kontrol).`);
  if (down.length) bullets.push(`Şu an erişilemeyen: ${down.map((r) => `<b>${esc(r.site.name)}</b>`).join(", ")}.`);
  if (crit.length) bullets.push(`Öncelik: ${crit.slice(0, 3).map((x) => `${esc(x.site.name)} — ${esc(x.i.title)}`).join("; ")}.`);
  const lead = crit.length || down.length
    ? "Acil müdahale gerektiren bulgu var."
    : open.some((x) => x.i.severity === "high")
      ? "Kritik sorun yok; yüksek önemli bulgular takip edilmeli."
      : "Genel durum sakin; açık kritik ya da yüksek bulgu yok.";
  return `<p><b>${lead}</b></p><ul>${bullets.map((b) => `<li>${b}</li>`).join("")}</ul>`;
}

function assetCard({ site, st }: Row, now: number): string {
  const h = siteHealth(site, st);
  const open = openIncidents(st);
  const s = h === "down" || (h === "issues" && open.some((i) => i.severity === "critical")) ? "bad" : h === "issues" ? "warn" : h === "ok" ? "ok" : "";
  return `<a class="asset s-${s}" href="/site/${esc(site.id)}"><div class="top"><span class="ty">${ASSET_LABEL.web[0]}</span><span class="nm">${esc(site.name)}</span><span class="dot ${HEALTH[h][1]}" title="${HEALTH[h][0]}"></span></div>
<div class="or">${esc(site.origin.replace(/^https?:\/\//, ""))}</div>
<div class="ft"><span>${HEALTH[h][0]}<br>Bulgu <b>${open.filter((i) => i.severity !== "info").length}</b> · Erişim <b>${uptimePct(st)}</b><br>Son: ${ago(st?.lastRun ?? null, now)}</span>${sparkline(st?.history ?? [])}</div></a>`;
}

function externalAssetCard(a: ExternalAsset): string {
  const dot = a.status === "unknown" ? "muted" : a.status;
  return `<div class="asset s-${a.status}"><div class="top"><span class="ty">${ASSET_LABEL[a.kind][0]}</span><span class="nm">${esc(a.name)}</span><span class="dot ${dot}"></span></div>
<div class="or">${esc(a.detail ?? ASSET_LABEL[a.kind][1])}</div><div class="ft"><span>Kaynak: <b>${esc(a.source)}</b></span></div></div>`;
}

const PLACEHOLDER: [AssetKind, string][] = [
  ["ios", "Uygulama izleme bağlandığında görünür"],
  ["android", "Uygulama izleme bağlandığında görünür"],
  ["api", "Uptime Kuma bağlandığında görünür"],
  ["server", "Wazuh ajanı bağlandığında görünür"],
];

const ICON: Record<string, string> = {
  genel: `<rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/>`,
  varliklar: `<rect x="3" y="4" width="18" height="7" rx="2"/><rect x="3" y="13" width="18" height="7" rx="2"/><path d="M7 7.5h.01M7 16.5h.01"/>`,
  bulgular: `<path d="M12 3 2 20h20z"/><path d="M12 10v4M12 17h.01"/>`,
  olaylar: `<path d="M3 12h4l3-8 4 16 3-8h4"/>`,
  aksiyonlar: `<path d="M9 11l3 3 8-8"/><path d="M20 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11"/>`,
  ip: `<circle cx="12" cy="12" r="9"/><path d="M5.6 5.6l12.8 12.8"/>`,
  ekle: `<path d="M12 5v14M5 12h14"/>`,
  plug: `<path d="M9 2v6M15 2v6M6 8h12v4a6 6 0 0 1-12 0zM12 18v4"/>`,
  ekip: `<circle cx="9" cy="8" r="3.5"/><path d="M2.5 20a6.5 6.5 0 0 1 13 0M16 4.5a3.5 3.5 0 0 1 0 7M18 14a6.5 6.5 0 0 1 3.5 6"/>`,
  kayit: `<path d="M8 3h8l3 3v15H5V3z"/><path d="M9 9h6M9 13h6M9 17h4"/>`,
  hesap: `<circle cx="12" cy="8" r="4"/><path d="M4 21a8 8 0 0 1 16 0"/>`,
};
const icon = (k: string) => `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${ICON[k]}</svg>`;

export interface NavData {
  /** Bölüm bağlantılarının öneki: panelde "" (aynı sayfa), diğer sayfalarda "/" */
  base: string;
  ctx: PanelCtx;
  /** Ayrı sayfalardan hangisi açık: ekip, kayit, hesap */
  page?: string;
  sites: { id: string; name: string; health: Health }[];
  currentSite?: string;
  counts?: { findings: number; crit: number; high: number; actions: number; urgentActions: boolean; ips: number | null };
  integrations?: { uptimeKuma: boolean; wazuh: boolean; ai: boolean };
}

export function sidebar(nav: NavData): string {
  const c = nav.counts;
  const cnt = (n: number | null | undefined, cls = "") => (n ? `<span class="cnt ${cls}">${n}</span>` : "");
  const item = (key: string, label: string, extra = "") => `<a data-nav="${key}" href="${nav.base}#${key}">${icon(key)}<span class="nm">${label}</span>${extra}</a>`;
  const integ = nav.integrations ?? { uptimeKuma: false, wazuh: false, ai: false };
  const pageItem = (key: string, href: string, label: string) => `<a href="${href}"${nav.page === key ? ' class="on"' : ""}>${icon(key)}<span class="nm">${label}</span></a>`;
  const { ctx } = nav;
  const orgSel =
    ctx.orgs.length > 1
      ? `<form class="orgsel" method="post" action="/org/sec"><label for="org" class="sr" style="margin:0 0 4px;font-size:11px;color:var(--muted);font-weight:600;letter-spacing:.08em;text-transform:uppercase">Organizasyon</label><select id="org" name="org" onchange="this.form.submit()">${ctx.orgs.map((o) => `<option value="${esc(o.id)}"${o.id === ctx.orgId ? " selected" : ""}>${esc(o.name)}</option>`).join("")}</select><noscript><button style="margin-top:6px">Seç</button></noscript></form>`
      : "";
  const intItem = (label: string, on: boolean) => `<span class="it">${icon("plug")}<span class="nm">${label}</span><span class="dot ${on ? "ok" : "muted"}" title="${on ? "bağlı" : "bağlı değil"}" style="box-shadow:none"></span></span>`;
  return `<nav class="side" aria-label="Panel menüsü">${orgSel}
<div class="sg">İzleme</div>
${item("genel", "Genel bakış")}
${item("varliklar", "Varlıklar", cnt(nav.sites.length))}
${item("bulgular", "Bulgular", cnt(c?.findings, c?.crit ? "crit" : c?.high ? "high" : ""))}
${item("olaylar", "Olay akışı")}
<div class="sg">Müdahale</div>
${item("aksiyonlar", "Onay bekleyenler", cnt(c?.actions, c?.urgentActions ? "high" : ""))}
${item("ip", "Engellenen IP'ler", cnt(c?.ips))}
${can.manageSites(ctx.role) ? item("ekle", "Site ekle") : ""}
<div class="sg">Yönetim</div>
${pageItem("ekip", "/ekip", "Ekip")}
${can.viewAudit(ctx.role) ? pageItem("kayit", "/kayit", "Erişim kaydı") : ""}
${pageItem("hesap", "/hesap", "Hesabım")}
<div class="grp-x"><div class="sg">Web siteleri</div>
${nav.sites.map((s) => `<a href="/site/${esc(s.id)}"${s.id === nav.currentSite ? ' class="on"' : ""}><span class="dot ${HEALTH[s.health][1]}" style="box-shadow:none;margin:0 4px"></span><span class="nm">${esc(s.name)}</span></a>`).join("") || `<span class="it"><span class="nm">Henüz site yok</span></span>`}
<div class="sg">Entegrasyonlar</div>
${intItem("Uptime Kuma", integ.uptimeKuma)}${intItem("Wazuh", integ.wazuh)}${intItem("Yapay zekâ özeti", integ.ai)}</div>
</nav>`;
}

export const viewHead = (title: string, sub: string, right = "") => `<div class="vh"><div><h1>${title}</h1><p>${sub}</p></div>${right}</div>`;

export function dashboard(rows: Row[], msg: string | null, isErr: boolean, feeds: ExternalFeeds = {}, ctx: PanelCtx = DEFAULT_CTX): string {
  const now = Date.now();
  const manage = can.manageSites(ctx.role);
  const score = riskScore(rows);
  const [riskText, riskCls] = riskLevel(score);
  const active = rows.filter((r) => !r.site.paused);
  const stale = active.filter((r) => !r.st?.lastRun || now - Date.parse(r.st.lastRun) > (r.site.intervalMin * 2 + 10) * 60000);
  const paused = rows.length - active.length;
  const prot: [string, string] = !active.length
    ? ["Koruma pasif", "muted"]
    : stale.length || paused
      ? ["Kısmi koruma", "warn"]
      : riskCls === "bad"
        ? ["Koruma aktif · tehdit var", "bad"]
        : ["Koruma aktif", "ok"];

  const findings = rows
    .flatMap(({ site, st }) => openIncidents(st).map((i) => ({ i, site })))
    .sort((a, b) => bySeverity(a.i, b.i) || Date.parse(b.i.since) - Date.parse(a.i.since));
  const n = (s: Severity) => findings.filter((f) => f.i.severity === s).length;
  const events = rows.flatMap(({ site, st }) => (st?.events ?? []).map((e) => ({ e, site }))).sort((a, b) => Date.parse(b.e.at) - Date.parse(a.e.at));
  const history = rows.flatMap((r) => r.st?.history ?? []);
  const hist24 = history.filter((p) => Date.parse(p.at) >= now - 24 * 3600_000);
  const up24 = hist24.length ? `%${((hist24.filter((p) => p.up).length / hist24.length) * 100).toFixed(1)}` : "—";
  const lastRun = rows.map((r) => r.st?.lastRun).filter((x): x is string => !!x).sort().pop() ?? null;
  const actions = pendingActions(rows, feeds.actions ?? []);
  const urgentActions = actions.some((a) => a.severity !== "info");
  const ext = feeds.assets ?? [];
  const missing = PLACEHOLDER.filter(([k]) => !ext.some((a) => a.kind === k));
  const ips = feeds.blockedIps;

  const riskCard = `<section class="card"><header><h2>Genel risk puanı</h2><span class="tag ${riskCls}">${riskText}</span></header>
<div class="risk">${gauge(score)}<div><div class="num">${score ?? "—"}<span class="of"> /100</span></div><div class="small" style="margin-top:6px">Açık bulguların ağırlıklı toplamı<br>Kritik 30 · Yüksek 12 · Öneri 2</div></div></div>
<div class="prot"><div class="row"><span>Koruma durumu</span><span class="tag ${prot[1]}">${prot[0]}</span></div>
<div class="row"><span>Aktif izleme</span><span>${active.length} / ${rows.length} varlık${paused ? ` · ${paused} duraklatıldı` : ""}</span></div>
<div class="row"><span>Geciken kontrol</span><span>${stale.length ? `<span style="color:var(--warn)">${stale.length} varlık</span>` : "yok"}</span></div>
<div class="row"><span>Son kontrol</span><span>${ago(lastRun, now)}</span></div></div></section>`;

  const kpi = (href: string, label: string, value: string | number, cls: string, sub: string) =>
    `<a class="kpi" href="#${href}"><div class="l">${label}</div><div class="v ${cls}">${value}</div><div class="s">${sub}</div></a>`;
  const kpis = `<div class="kpis">
${kpi("varliklar", "İzlenen varlık", rows.length + ext.length, "", `${rows.length} web${ext.length ? ` · ${ext.length} dış kaynak` : ""}`)}
${kpi("bulgular", "Kritik bulgu", n("critical"), n("critical") ? "crit" : "ok", "hemen müdahale")}
${kpi("bulgular", "Yüksek bulgu", n("high"), n("high") ? "high" : "ok", `${n("info")} öneri ayrıca`)}
${kpi("genel", "24 saat erişim", up24, "", `${hist24.length} kontrol`)}
${kpi("ip", "Engellenen IP", ips ? ips.length : "—", "", ips ? "son 24 saat" : "kaynak bağlı değil")}
${kpi("aksiyonlar", "Bekleyen aksiyon", actions.length, urgentActions ? "high" : "", "onayınızı bekliyor")}</div>`;

  const chartCard = `<section class="card"><header><h2>24 saatlik erişim</h2><span class="count">tüm web varlıkları · saatlik</span></header>${accessChart(history, now)}</section>`;

  const ai = feeds.aiSummary;
  const aiCard = `<section class="card ai"><header><h2>Günlük özet</h2><span class="chip">${ai ? "Yapay zekâ" : "Kural tabanlı"}</span></header>
${ai ? `<p style="white-space:pre-line">${esc(ai.text)}</p><div class="src">${esc(ai.model ?? "Yapay zekâ")} · ${esc(fmt(ai.at))}</div>` : `${ruleSummary(rows, now)}<div class="src">Yapay zekâ özeti henüz bağlı değil; bu özet panel verilerinden otomatik üretildi.</div>`}</section>`;

  const urgent = findings.filter((f) => f.i.severity !== "info");
  const priorityCard = `<section class="card"><header><h2>Öncelikli bulgular</h2><span class="count">${urgent.length} kritik / yüksek</span></header>
${urgent.length ? `<ul class="find">${urgent.slice(0, 3).map((f) => findingItem(f.i, f.site, now)).join("")}</ul>` : emptyState("Kritik ya da yüksek bulgu yok", rows.length ? "Sadece öneri seviyesinde bulgular var." : "Henüz izlenen varlık yok.")}
<a class="more" href="#bulgular">Tüm bulgular (${findings.length}) →</a></section>`;

  const recentCard = `<section class="card"><header><h2>Son olaylar</h2></header>
${events.length ? `<ul class="feed">${events.slice(0, 6).map((x) => eventItem(x.e, x.site, now)).join("")}</ul><a class="more" href="#olaylar">Olay akışı →</a>` : emptyState("Olay yok", "Bulgu açıldığında ya da düzeldiğinde burada görünür.")}</section>`;

  const genel = `<section data-view="genel">${viewHead("Genel bakış", `${prot[0]} · ${clock(now)} itibarıyla`)}
<div class="grid g-top">${riskCard}${kpis}</div>
<div class="grid g-main sec"><div class="stack">${chartCard}${priorityCard}</div><div class="stack">${aiCard}${recentCard}</div></div></section>`;

  const varliklar = `<section data-view="varliklar">${viewHead("Varlıklar", "İzlenen web siteleri ve bağlanacak diğer kaynaklar", manage ? `<a class="btn" href="#ekle">+ Site ekle</a>` : "")}
<div class="assets">${rows.map((r) => assetCard(r, now)).join("")}${ext.map(externalAssetCard).join("")}
${rows.length || !manage ? "" : `<a class="asset empty" href="#ekle"><div class="top"><span class="ty">WEB</span><span class="nm">Web sitesi</span></div><div class="or" style="margin-bottom:0">İlk sitenizi eklemek için tıklayın</div></a>`}
${missing.map(([k, t]) => `<div class="asset empty"><div class="top"><span class="ty">${ASSET_LABEL[k][0]}</span><span class="nm">${ASSET_LABEL[k][1]}</span><span class="chip">bağlı değil</span></div><div class="or" style="margin-bottom:0">${t}</div></div>`).join("")}</div></section>`;

  const bulgular = `<section data-view="bulgular">${viewHead("Bulgular", `Önem sırasına göre · ${n("critical")} kritik, ${n("high")} yüksek, ${n("info")} öneri`)}
<section class="card">${findings.length ? `<ul class="find">${findings.map((f) => findingItem(f.i, f.site, now)).join("")}</ul>` : emptyState("Açık bulgu yok", rows.length ? "Tüm kontroller temiz geçti." : "Henüz izlenen varlık yok.")}</section></section>`;

  const olaylar = `<section data-view="olaylar">${viewHead("Olay akışı", "Tüm sitelerde açılan, düzelen ve bildirilen olaylar")}
<section class="card">${events.length ? `<ul class="feed">${events.slice(0, 100).map((x) => eventItem(x.e, x.site, now)).join("")}</ul>${events.length > 100 ? `<p class="small">Son 100 olay gösteriliyor; daha eskiler site sayfalarında.</p>` : ""}` : emptyState("Olay yok", "Bulgu açıldığında ya da düzeldiğinde burada görünür.")}</section></section>`;

  const aksiyonlar = `<section data-view="aksiyonlar">${viewHead("Onay bekleyen aksiyonlar", "İnsan kararı gerektiren işlemler")}
<section class="card">${actions.length ? `<ul class="list">${actions.map((a) => `<li><span class="tag sev ${SEV[a.severity].cls}">${SEV[a.severity].label}</span><span class="grow"><b>${esc(a.title)}</b><br><span class="sm">${esc(a.detail)}</span></span>${safeHref(a.href) ? `<a class="btn" href="${safeHref(a.href)}">İncele</a>` : `<span class="chip">${esc(a.source)}</span>`}</li>`).join("")}</ul>` : emptyState("Bekleyen aksiyon yok", "Onayınızı gerektiren bir işlem bulunmuyor.")}</section></section>`;

  const ipView = `<section data-view="ip">${viewHead("Engellenen IP'ler", ips ? "Son 24 saatte engellenen adresler" : "Kaynak bağlı değil")}
<section class="card">${ips?.length ? `<table><thead><tr><th>IP</th><th>Neden</th><th class="hide-sm">Zaman</th></tr></thead><tbody>${ips.slice(0, 200).map((b) => `<tr><td class="ip">${esc(b.ip)}</td><td>${esc(b.reason)}<br><span class="small">${esc(b.source)}${b.asset ? ` · ${esc(b.asset)}` : ""}</span></td><td class="hide-sm small">${esc(ago(b.at, now))}</td></tr>`).join("")}</tbody></table>` : ips ? emptyState("Engellenen IP yok", "Son 24 saatte engelleme yapılmadı.") : emptyState("Kaynak bağlı değil", "Gözcü dışarıdan izler, IP engellemez. Wazuh active-response bağlandığında engellenen adresler burada listelenir.")}</section></section>`;

  const ekle = !manage ? "" : `<section data-view="ekle">${viewHead("Site ekle", "Sahibi olduğunuz ya da izleme izni aldığınız bir web sitesini izlemeye alın")}${addSiteForm()}</section>`;

  const side = sidebar({
    base: "",
    ctx,
    sites: rows.map(({ site, st }) => ({ id: site.id, name: site.name, health: siteHealth(site, st) })),
    counts: { findings: findings.length, crit: n("critical"), high: n("high"), actions: actions.length, urgentActions, ips: ips ? ips.length : null },
    integrations: { uptimeKuma: ext.some((a) => /uptime kuma/i.test(a.source)), wazuh: !!ips || ext.some((a) => /wazuh/i.test(a.source)), ai: !!ai },
  });

  // Panel açıkken dakikada bir tazelenir; form doldurulurken ya da "Site ekle" bölümündeyken dokunmaz.
  const script = `setInterval(function(){if(document.hidden||location.hash==='#ekle')return;var a=document.activeElement;if(a&&/INPUT|TEXTAREA|SELECT/.test(a.tagName))return;location.replace('/'+location.hash)},60000)`;
  const body = `${flash(msg, isErr)}${genel}${varliklar}${bulgular}${olaylar}${aksiyonlar}${ipView}${ekle}`;
  return layout("Güvenlik paneli", body, { authed: true, status: [`${prot[0]} · ${clock(now)}`, prot[1]], script, side, account: ctx });
}

function resultsByKind(results: CheckResult[]): string {
  const order: Kind[] = ["uptime", "https", "redirect", "script", "exposed", "headers", "dns"];
  return `<div class="res">${order
    .map((k) => {
      const items = results.filter((r) => r.kind === k);
      if (!items.length) return "";
      const bad = items.filter((r) => !r.ok);
      const cls = bad.length ? (k === "headers" ? "muted" : "bad") : "ok";
      const label = bad.length ? (k === "headers" ? `${bad.length} öneri` : `${bad.length} sorun`) : "Temiz";
      const lines =
        k === "exposed"
          ? `<div class="line">${items.length} dosya denendi${bad.length ? "" : ", hiçbiri indirilemiyor"}</div>${bad.map((r) => `<div class="line"><code>${esc(r.id.split(":").slice(1).join(":"))}</code> ${esc(r.detail)}</div>`).join("")}`
          : items.map((r) => `<div class="line">${r.ok ? "✓ " : "⚠ "}${esc(r.ok ? r.detail : r.title + " — " + r.detail)}</div>`).join("");
      return `<div class="card"><div style="display:flex;justify-content:space-between;gap:8px;margin-bottom:4px"><b>${KIND_LABEL[k]}</b><span class="tag ${cls}">${label}</span></div>${lines}</div>`;
    })
    .join("")}</div>`;
}

export function siteDetail(site: SiteConfig, st: SiteState | null, msg: string | null, isErr: boolean, ctx: PanelCtx = DEFAULT_CTX): string {
  const now = Date.now();
  const manage = can.manageSites(ctx.role);
  const h = siteHealth(site, st);
  const open = openIncidents(st).sort(bySeverity);
  const score = riskScore([{ site: { ...site, paused: false }, st }]);
  const [riskText, riskCls] = riskLevel(score);
  const worst = open.some((i) => i.severity === "critical") ? "crit" : open.some((i) => i.severity === "high") ? "high" : "ok";
  const btn = (action: string, label: string, extra = "") =>
    `<form class="inline" method="post" action="/site/${esc(site.id)}/${action}"${extra}><button${action === "delete" ? ' class="danger"' : action === "run" ? ' class="primary"' : ""}>${label}</button></form>`;
  const body = `<div class="crumb"><a href="/">Panel</a> / <a href="/#varliklar">Varlıklar</a> / ${esc(site.name)}</div>${flash(msg, isErr)}
<section class="card"><div style="display:flex;justify-content:space-between;gap:16px;flex-wrap:wrap;align-items:flex-start">
<div style="min-width:0"><div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap"><span class="ty">WEB</span><h1>${esc(site.name)}</h1><span class="tag ${HEALTH[h][1]}">${HEALTH[h][0]}</span></div>
<a class="small" style="font-family:var(--mono);word-break:break-all" href="${esc(site.origin)}" rel="noopener noreferrer" target="_blank">${esc(site.origin)}</a></div>
${manage ? `<div class="actions">${btn("run", "Şimdi kontrol et")}${btn("test-mail", "Test e-postası")}${btn(site.paused ? "resume" : "pause", site.paused ? "Devam ettir" : "Duraklat")}
${btn("reset", "Script referansını sıfırla", ` onsubmit="return confirm('Sayfadaki mevcut dış kaynaklar yeniden &quot;bilinen&quot; kabul edilecek. Devam?')"`)}${btn("delete", "Sil", ` onsubmit="return confirm('Bu site ve geçmişi silinecek. Emin misiniz?')"`)}</div>` : `<span class="chip">Görüntüleme yetkisi</span>`}</div>
<div class="kpis" style="margin-top:16px">
<div class="kpi"><div class="l">Risk puanı</div><div class="v">${score ?? "—"}</div><div class="s"><span class="tag ${riskCls}">${riskText}</span></div></div>
<div class="kpi"><div class="l">Açık bulgu</div><div class="v ${worst}">${open.filter((i) => i.severity !== "info").length}</div><div class="s">${open.filter((i) => i.severity === "info").length} öneri ayrıca</div></div>
<div class="kpi"><div class="l">24 saat erişim</div><div class="v">${uptimePct(st)}</div><div class="s">${st?.history.length ?? 0} kontrol</div></div>
<div class="kpi"><div class="l">Son kontrol</div><div class="v" style="font-size:18px;padding:5px 0 3px">${ago(st?.lastRun ?? null, now)}</div><div class="s">${st?.lastRun ? `${st.lastDurationMs} ms · toplam ${st.runs} kontrol` : "henüz yok"}</div></div>
</div>
<dl class="kv" style="margin-top:16px"><dt>Sıklık</dt><dd>${site.intervalMin} dakika</dd>
<dt>Uyarı e-postası</dt><dd>${site.emails.length ? esc(site.emails.join(", ")) : '<span class="tag warn">tanımlı değil</span>'}${st?.lastMail ? ` <span class="small">· son gönderim ${fmt(st.lastMail.at)} ${st.lastMail.ok ? "✓" : "✗ " + esc(st.lastMail.error ?? "")}</span>` : ""}</dd></dl></section>
<div class="grid g-main sec"><section class="card"><header><h2>Bulgular · önem sırasına göre</h2><span class="count">${open.length} açık</span></header>
${open.length ? `<ul class="find">${open.map((i) => findingItem(i, null, now)).join("")}</ul>` : emptyState("Açık bulgu yok", st?.lastRun ? "Son kontrolde sorun bulunmadı." : "Henüz kontrol yapılmadı.")}</section>
<section class="card"><header><h2>24 saatlik erişim</h2></header>${accessChart(st?.history ?? [], now)}</section></div>
<section class="card sec"><header><h2>Son kontrol sonuçları</h2><span class="count">${st?.lastRun ? fmt(st.lastRun) : ""}</span></header>${st?.lastResults.length ? resultsByKind(st.lastResults) : emptyState("Henüz kontrol yapılmadı", '"Şimdi kontrol et"e basın.')}</section>
<section class="card sec"><header><h2>Olay geçmişi</h2><span class="count">${st?.events.length ?? 0}</span></header>${
    st?.events.length ? `<ul class="feed scroll">${st.events.slice(0, 50).map((e) => eventItem(e, null, now)).join("")}</ul>` : emptyState("Olay yok", "Bulgu açıldığında ya da düzeldiğinde burada görünür.")
  }</section>
${manage ? `<details class="card fold sec"><summary><h2>Ayarlar</h2>${toggle("Düzenle")}</summary><form method="post" action="/site/${esc(site.id)}/edit" style="margin-top:6px">
<label for="name">Görünen ad</label><input id="name" type="text" name="name" value="${esc(site.name)}">
<label for="emails">Uyarı e-postaları</label><textarea id="emails" name="emails">${esc(site.emails.join("\n"))}</textarea>
<div class="cols"><div><label for="pages">Ek kontrol sayfaları</label><textarea id="pages" name="pages">${esc(site.pages.filter((p) => p !== "/").join("\n"))}</textarea></div>
<div><label for="extra">Siteye özel hassas dosyalar</label><textarea id="extra" name="extraPaths">${esc(site.extraPaths.join("\n"))}</textarea></div></div>
<label for="iv">Kontrol sıklığı</label><select id="iv" name="intervalMin">${[5, 15, 60].map((v) => `<option value="${v}"${site.intervalMin === v ? " selected" : ""}>${v === 60 ? "Saatte bir" : v + " dakikada bir"}</option>`).join("")}</select>
<input type="hidden" name="ownerConfirmed" value="1"><p style="margin:16px 0 0"><button class="primary">Kaydet</button></p></form></details>` : ""}`;
  const side = sidebar({ base: "/", ctx, sites: ctx.sites ?? [{ id: site.id, name: site.name, health: h }], currentSite: site.id });
  return layout(site.name, body, { authed: true, status: [`${HEALTH[h][0]} · ${clock(now)}`, HEALTH[h][1]], side, account: ctx });
}
