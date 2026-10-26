/**
 * Hesap ekranları: iki adımlı doğrulama, davet, ekip, erişim kaydı, hesabım. Tüm kullanıcı verisi esc() ile kaçırılır.
 */
import { esc } from "./alert";
import { ROLE_LABEL, ROLES, can, type Invite, type Member, type Role } from "./accounts";
import { AUDIT_LABEL, type AuditRow } from "./audit";
import { PASSWORD_MIN } from "./security";
import { emptyState, flash, fmt, layout, sidebar, viewHead, type PanelCtx } from "./ui";

function appPage(title: string, body: string, ctx: PanelCtx, page: string): string {
  return layout(title, body, { authed: true, account: ctx, side: sidebar({ base: "/", ctx, sites: ctx.sites ?? [], page }) });
}

const center = (inner: string) => `<div class="center" style="max-width:460px">${inner}</div>`;
const card = (title: string, inner: string) => `<div class="card"><header><h2>${title}</h2></header>${inner}</div>`;

const passwordFields = (autofocus = true) => `<label for="p1" style="margin-top:0">Şifre <small>(en az ${PASSWORD_MIN} karakter)</small></label>
<input id="p1" type="password" name="password" autocomplete="new-password" minlength="${PASSWORD_MIN}" maxlength="128" required${autofocus ? " autofocus" : ""}>
<label for="p2">Şifre (tekrar)</label><input id="p2" type="password" name="password2" autocomplete="new-password" minlength="${PASSWORD_MIN}" maxlength="128" required>`;

// ——— İki adımlı doğrulama ———

export function totpPage(error: string | null): string {
  return layout(
    "Doğrulama",
    center(`${flash(error, true)}${card(
      "İki adımlı doğrulama",
      `<p class="small" style="margin-top:0">Doğrulama uygulamanızdaki 6 haneli kodu girin.</p>
<form method="post" action="/2fa"><label for="c" style="margin-top:0">Kod</label>
<input id="c" type="text" name="code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9 ]{6,7}" maxlength="7" required autofocus style="font:600 20px var(--mono);letter-spacing:.3em">
<p style="margin:16px 0 0"><button class="primary">Doğrula</button></p></form>
<details style="margin-top:16px"><summary class="small" style="cursor:pointer">Telefonuma erişemiyorum — kurtarma kodu kullan</summary>
<form method="post" action="/2fa" style="margin-top:8px"><label for="r" style="margin-top:0">Kurtarma kodu</label><input id="r" type="text" name="recovery" autocomplete="off" placeholder="xxxxx-xxxxx" required>
<p style="margin:12px 0 0"><button>Kurtarma koduyla gir</button></p></form></details>`,
    )}<form method="post" action="/logout" style="text-align:center;margin-top:12px"><button>Vazgeç</button></form>`),
  );
}

export function totpSetupPage(qrSvg: string, secret: string, email: string, error: string | null): string {
  const grouped = secret.replace(/(.{4})/g, "$1 ").trim();
  return layout(
    "İki adımlı doğrulama kurulumu",
    center(`${flash(error, true)}${card(
      "İki adımlı doğrulamayı kurun",
      `<p class="small" style="margin-top:0">Panele girmek için zorunlu. Google Authenticator, Microsoft Authenticator, 1Password ya da Bitwarden gibi bir uygulamayla aşağıdaki kodu tarayın.</p>
<div style="background:#fff;border-radius:10px;padding:12px;width:220px;margin:8px auto">${qrSvg}</div>
<p class="small" style="text-align:center;margin:6px 0 0">Tarayamıyorsanız elle girin:<br><code style="font-size:13px;user-select:all">${esc(grouped)}</code><br>Hesap: ${esc(email)}</p>
<form method="post" action="/2fa/kurulum"><label for="c">Uygulamadaki 6 haneli kod</label>
<input id="c" type="text" name="code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9 ]{6,7}" maxlength="7" required autofocus style="font:600 20px var(--mono);letter-spacing:.3em">
<p style="margin:16px 0 0"><button class="primary">Etkinleştir</button></p></form>`,
    )}<form method="post" action="/logout" style="text-align:center;margin-top:12px"><button>Vazgeç</button></form>`),
  );
}

export function recoveryCodesPage(codes: string[], next = "/"): string {
  return layout(
    "Kurtarma kodları",
    center(card(
      "Kurtarma kodlarınız",
      `<p class="small" style="margin-top:0">Telefonunuzu kaybederseniz bu kodlarla girebilirsiniz. Her kod <b>bir kez</b> kullanılır. Bir şifre yöneticisine kaydedin; bu sayfa bir daha gösterilmez.</p>
<pre style="font:15px/1.9 var(--mono);background:var(--panel2);border:1px solid var(--line);border-radius:10px;padding:12px 16px;columns:2;user-select:all;margin:12px 0">${codes.map(esc).join("\n")}</pre>
<p style="margin:16px 0 0"><a class="btn" href="${esc(next)}" style="background:var(--accent);border-color:var(--accent);color:var(--onaccent);font-weight:600">Kaydettim, panele geç</a></p>`,
    )),
  );
}

// ——— Davet ———

export type InviteView =
  | { kind: "invalid" }
  | { kind: "register"; invite: Invite; error: string | null }
  | { kind: "login"; invite: Invite; token: string }
  | { kind: "accept"; invite: Invite; error: string | null }
  | { kind: "wrong-account"; invite: Invite; email: string };

export function invitePage(v: InviteView, token = ""): string {
  if (v.kind === "invalid")
    return layout("Davet", center(card("Davet geçersiz", `<p style="margin:0">Bu davet bağlantısı kullanılmış, iptal edilmiş ya da süresi dolmuş. Davet edenden yeni bir davet isteyin.</p><p style="margin:14px 0 0"><a href="/login">Girişe dön</a></p>`)));
  const inv = v.invite;
  const intro = `<p style="margin-top:0"><b>${esc(inv.orgName)}</b> organizasyonuna <b>${ROLE_LABEL[inv.role]}</b> olarak davet edildiniz${inv.invitedByEmail ? ` <span class="small">(davet eden: ${esc(inv.invitedByEmail)})</span>` : ""}.</p>
<dl class="kv" style="margin:0 0 6px"><dt>E-posta</dt><dd>${esc(inv.email)}</dd><dt>Son geçerlilik</dt><dd>${fmt(inv.expiresAt.toISOString())}</dd></dl>`;
  const action = `/davet/${esc(token)}`;
  switch (v.kind) {
    case "register":
      return layout("Davet", center(`${flash(v.error, true)}${card("Hesap oluşturun", `${intro}<form method="post" action="${action}">${passwordFields()}
<p class="small">Sonraki adımda iki adımlı doğrulamayı kuracaksınız.</p><p style="margin:12px 0 0"><button class="primary">Hesabı oluştur</button></p></form>`)}`));
    case "login":
      return layout("Davet", center(card("Daveti kabul edin", `${intro}<p>Bu e-postayla zaten bir hesabınız var. Daveti kabul etmek için giriş yapın.</p>
<p style="margin:12px 0 0"><a class="btn" href="/login?next=${encodeURIComponent(`/davet/${v.token}`)}&amp;email=${encodeURIComponent(inv.email)}">Giriş yap</a></p>`)));
    case "accept":
      return layout("Davet", center(`${flash(v.error, true)}${card("Daveti kabul edin", `${intro}<form method="post" action="${action}"><p style="margin:12px 0 0"><button class="primary">Katıl</button></p></form>`)}`));
    case "wrong-account":
      return layout("Davet", center(card("Farklı hesapla girdiniz", `${intro}<p>Şu an <b>${esc(v.email)}</b> olarak girişlisiniz. Bu davet başka bir e-posta adresine gönderildi.</p>
<form method="post" action="/logout"><button>Çıkış yap</button></form>`)));
  }
}

// ——— Ekip ———

export function teamPage(ctx: PanelCtx, members: Member[], invites: Invite[], me: string, msg: string | null, isErr: boolean): string {
  const roleOpts = (cur: Role) => ROLES.filter((r) => can.inviteAs(ctx.role, r) || r === cur).map((r) => `<option value="${r}"${r === cur ? " selected" : ""}>${ROLE_LABEL[r]}</option>`).join("");
  const memberRow = (m: Member) => {
    const editable = m.userId !== me && can.changeMember(ctx.role, m.role);
    return `<tr><td><b>${esc(m.email)}</b>${m.userId === me ? ' <span class="chip">siz</span>' : ""}<br><span class="small">${m.lastLoginAt ? `son giriş ${fmt(m.lastLoginAt.toISOString())}` : "henüz giriş yapmadı"}${m.totpEnabled ? "" : ' · <span style="color:var(--warn)">2FA kurulmadı</span>'}</span></td>
<td>${editable ? `<form class="inline" method="post" action="/ekip/uye/${esc(m.userId)}/rol"><select name="role" onchange="this.form.submit()" aria-label="Rol" style="width:auto">${roleOpts(m.role)}</select><noscript><button>Kaydet</button></noscript></form>` : `<span class="tag ${m.role === "owner" ? "ok" : "muted"}">${ROLE_LABEL[m.role]}</span>`}</td>
<td style="text-align:right">${editable ? `<form class="inline" method="post" action="/ekip/uye/${esc(m.userId)}/cikar" onsubmit="return confirm('${esc(m.email)} organizasyondan çıkarılacak. Emin misiniz?')"><button class="danger">Çıkar</button></form>` : ""}</td></tr>`;
  };
  const inviteForm = can.invite(ctx.role)
    ? `<section class="card sec" style="max-width:720px"><header><h2>Ekip daveti</h2></header><form method="post" action="/ekip/davet">
<div class="cols"><div><label for="ie" style="margin-top:0">E-posta</label><input id="ie" type="text" inputmode="email" name="email" placeholder="ad@sirket.com" required></div>
<div><label for="ir" style="margin-top:0">Rol</label><select id="ir" name="role">${ROLES.filter((r) => can.inviteAs(ctx.role, r)).map((r) => `<option value="${r}"${r === "viewer" ? " selected" : ""}>${ROLE_LABEL[r]}</option>`).join("")}</select></div></div>
<p class="small" style="margin:10px 0 0">Davet bağlantısı e-postayla gider, 7 gün geçerlidir ve bir kez kullanılır.</p>
<p style="margin:14px 0 0"><button class="primary">Davet gönder</button></p></form></section>`
    : "";
  const pending = invites.length
    ? `<section class="card sec"><header><h2>Bekleyen davetler</h2><span class="count">${invites.length}</span></header><table><thead><tr><th>E-posta</th><th>Rol</th><th class="hide-sm">Son geçerlilik</th><th></th></tr></thead><tbody>
${invites.map((i) => `<tr><td>${esc(i.email)}<br><span class="small">${i.invitedByEmail ? `davet eden ${esc(i.invitedByEmail)}` : ""}</span></td><td>${ROLE_LABEL[i.role]}</td><td class="hide-sm small">${fmt(i.expiresAt.toISOString())}</td>
<td style="text-align:right">${can.inviteAs(ctx.role, i.role) ? `<form class="inline" method="post" action="/ekip/davet/${esc(i.id)}/iptal"><button class="danger">İptal</button></form>` : ""}</td></tr>`).join("")}</tbody></table></section>`
    : "";
  const body = `${flash(msg, isErr)}${viewHead("Ekip", `${esc(ctx.orgName)} · ${members.length} üye`)}
<section class="card"><table><thead><tr><th>Üye</th><th>Rol</th><th></th></tr></thead><tbody>${members.map(memberRow).join("")}</tbody></table>
<p class="small" style="margin:12px 0 0"><b>Sahip</b>: her şey, rolleri ve sahipleri yönetir · <b>Yönetici</b>: siteleri yönetir, davet eder, erişim kaydını görür · <b>Görüntüleyen</b>: sadece izler</p></section>
${inviteForm}${pending}`;
  return appPage("Ekip", body, ctx, "ekip");
}

// ——— Erişim kaydı ———

function shortUa(ua: string | null): string {
  if (!ua) return "";
  const b = ua.match(/(Edg|Firefox|Chrome|Safari)\/[\d.]+/)?.[1]?.replace("Edg", "Edge") ?? "";
  const os = ua.match(/(Windows|Mac OS X|Android|iPhone|iPad|Linux)/)?.[1]?.replace("Mac OS X", "macOS") ?? "";
  return [b, os].filter(Boolean).join(" · ") || ua.slice(0, 40);
}

const BAD_ACTIONS = new Set(["login.fail", "login.locked", "login.unknown", "totp.fail", "access.denied"]);

export function auditPage(ctx: PanelCtx, rows: AuditRow[]): string {
  const body = `${viewHead("Erişim kaydı", "Girişler, başarısız denemeler, ekip ve site işlemleri · son 300 kayıt · 1 yıl saklanır")}
<section class="card">${
    rows.length
      ? `<div style="overflow-x:auto"><table><thead><tr><th>Zaman</th><th>Kim</th><th>İşlem</th><th class="hide-sm">IP / tarayıcı</th></tr></thead><tbody>${rows
          .map(
            (r) => `<tr><td class="small" style="white-space:nowrap;font-family:var(--mono)">${fmt(r.at.toISOString())}</td><td>${esc(r.email ?? "—")}</td>
<td>${BAD_ACTIONS.has(r.action) ? `<span class="tag bad">${esc(AUDIT_LABEL[r.action] ?? r.action)}</span>` : esc(AUDIT_LABEL[r.action] ?? r.action)}${r.target ? `<br><span class="small">${esc(r.target)}</span>` : ""}</td>
<td class="hide-sm small"><span style="font-family:var(--mono)">${esc(r.ip ?? "")}</span><br>${esc(shortUa(r.userAgent))}</td></tr>`,
          )
          .join("")}</tbody></table></div>`
      : emptyState("Kayıt yok", "Henüz kaydedilmiş bir işlem yok.")
  }</section>`;
  return appPage("Erişim kaydı", body, ctx, "kayit");
}

// ——— Hesabım ———

export function accountPage(ctx: PanelCtx, info: { recoveryLeft: number }, msg: string | null, isErr: boolean): string {
  const body = `${flash(msg, isErr)}${viewHead("Hesabım", esc(ctx.email))}
<div class="grid g-main"><section class="card"><header><h2>Şifre değiştir</h2></header><form method="post" action="/hesap/sifre">
<label for="cur" style="margin-top:0">Mevcut şifre</label><input id="cur" type="password" name="current" autocomplete="current-password" required>
<div style="margin-top:12px">${passwordFields(false)}</div>
<p class="small" style="margin:10px 0 0">Şifre değişince diğer cihazlardaki oturumlarınız kapanır.</p>
<p style="margin:14px 0 0"><button class="primary">Şifreyi değiştir</button></p></form></section>
<section class="card"><header><h2>İki adımlı doğrulama</h2><span class="tag ok">Etkin</span></header>
<p style="margin:0">Kalan kurtarma kodu: <b>${info.recoveryLeft}</b> / 8</p>
<p class="small">Kodlarınız azaldıysa ya da telefonunuzu değiştirdiyseniz sistem yöneticisinden 2FA sıfırlaması isteyin; bir sonraki girişte yeniden kurarsınız.</p>
<dl class="kv" style="margin-top:12px"><dt>Organizasyon</dt><dd>${esc(ctx.orgName)}</dd><dt>Rol</dt><dd>${ROLE_LABEL[ctx.role]}</dd></dl></section></div>`;
  return appPage("Hesabım", body, ctx, "hesap");
}
