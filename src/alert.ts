/** Uyarı e-postasının konusu ve HTML gövdesi. */
import { minutesSince } from "./incidents";
import type { Incident, Kind, SiteConfig } from "./types";

export const esc = (s: string) =>
  s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!);

export const ADVICE: Record<Kind, string> = {
  uptime: "Site ya da sayfa cevap vermiyor. Hosting / sunucu durumunu kontrol edin.",
  https: "Ziyaretçiler şifresiz bağlantıyla gelebiliyor. Hosting panelinden HTTPS yönlendirmesini açın.",
  redirect: "Ziyaretçiler başka bir siteye yönlendiriliyor. .htaccess / sunucu ayarlarını ve sayfaya gömülü scriptleri hemen kontrol edin.",
  script: "Sayfada daha önce olmayan bir dış kod var. Bilerek eklenmediyse site ele geçirilmiş olabilir; kaynağı kaldırın.",
  exposed: "Bu dosya herkes tarafından indirilebiliyor. Sunucudan silin; içinde şifre / anahtar varsa onları değiştirin.",
  headers: "Güvenlik başlığı eksik. Acil değil; hosting veya sunucu ayarından eklenebilir.",
  dns: "Alan adının DNS kaydı değişti. Bu değişikliği siz yapmadıysanız alan adı ve DNS hesaplarını kontrol edin.",
};

export interface Notice {
  id: string;
  kind: Kind;
  title: string;
  severity: Incident["severity"];
  detail: string;
}

export function buildAlert(site: SiteConfig, opened: Incident[], resolved: Incident[], notices: Notice[], now: string, panelUrl: string, isTest = false) {
  const critical = opened.some((i) => i.severity === "critical");
  const lead = isTest ? "Test e-postası" : (opened[0]?.title ?? notices[0]?.title ?? resolved[0]?.title ?? "");
  const total = opened.length + notices.length + resolved.length;
  const icon = isTest ? "✅" : critical ? "🔴" : opened.length || notices.length ? "🟠" : "🟢";
  const subject = `${icon} ${site.name}: ${lead}${total > 1 ? ` (+${total - 1})` : ""}`;

  const li = (title: string, detail: string, advice?: string) =>
    `<li style="margin-bottom:10px"><b>${esc(title)}</b><br>${esc(detail)}${advice ? `<br><span style="color:#555">${esc(advice)}</span>` : ""}</li>`;
  const block = (color: string, heading: string, items: string) =>
    `<h3 style="margin:18px 0 8px;color:${color};font-size:15px">${heading}</h3><ul style="padding-left:18px;margin:0">${items}</ul>`;

  let html = `<div style="font-family:Arial,sans-serif;font-size:14px;color:#111;max-width:640px">
<h2 style="margin:0 0 4px">${esc(site.name)} — Site Gözcü</h2>
<p style="margin:0;color:#666">${esc(site.origin)} · ${esc(new Date(now).toLocaleString("tr-TR", { timeZone: "Europe/Istanbul" }))}</p>`;
  if (isTest) html += `<p style="margin-top:16px">E-posta ayarları çalışıyor. Bu siteyle ilgili uyarılar bu adrese gelecek.</p>`;
  if (opened.length) html += block("#b91c1c", "Yeni sorunlar", opened.map((i) => li(i.title, i.detail, ADVICE[i.kind])).join(""));
  if (notices.length) html += block("#b45309", "Bildirimler", notices.map((n) => li(n.title, n.detail, ADVICE[n.kind])).join(""));
  if (resolved.length) html += block("#15803d", "Düzelenler", resolved.map((i) => li(i.title, `${minutesSince(i.since, now)} dk sürdü`)).join(""));
  html += `<p style="margin-top:20px;color:#666">${panelUrl ? `Ayrıntılar: <a href="${esc(panelUrl)}">Site Gözcü paneli</a>. ` : ""}Bu e-posta site dışında çalışan bir ajandan gelir; site kapalıyken de gönderilir.</p></div>`;
  return { subject, html };
}
