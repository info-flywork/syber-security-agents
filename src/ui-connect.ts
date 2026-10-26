/**
 * Varlık sayfasındaki "Bağlantı" bölümü: API anahtarları, tek seferlik secret gösterimi, .env örneği, kurulum talimatı.
 */
import { esc } from "./alert";
import { INGEST_PATH } from "./ingest";
import type { KeyMode, SiteKey } from "./apikeys";
import { ago, fmt } from "./ui";

const MODE_LABEL: Record<KeyMode, string> = { live: "Canlı (live)", test: "Test" };

export interface Revealed {
  mode: KeyMode;
  publicId: string;
  secret: string;
}

export interface ConnView {
  slug: string;
  keys: SiteKey[];
  publicUrl: string;
  manage: boolean;
  revealed?: Revealed;
  /** Bu varlığa gelen son olay */
  lastEventAt: string | null;
}

const copyLine = (id: string, value: string) =>
  `<div class="codeline"><code id="${id}">${esc(value)}</code><button type="button" class="copy" onclick="sgCopy('${id}',this)">Kopyala</button></div>`;

function envBlock(id: string, publicUrl: string, siteId: string, secret: string): string {
  return `<pre class="code" id="${id}">SITEGOZCU_URL=${esc(publicUrl)}
SITEGOZCU_SITE_ID=${esc(siteId)}
SITEGOZCU_SECRET=${esc(secret)}</pre><p style="margin:6px 0 0"><button type="button" class="copy" onclick="sgCopy('${id}',this)">.env satırlarını kopyala</button></p>`;
}

/** Anahtar oluşturulduğunda / yenilendiğinde sayfanın en üstünde bir kez gösterilir. Adres çubuğu site sayfasına çevrilir: yenilenince form tekrar gönderilmez, secret kaybolur. */
export function revealBox(r: Revealed, publicUrl: string, slug: string): string {
  return `<section class="reveal" role="alert"><h2 style="color:var(--warn)">Gizli anahtar — sadece şimdi gösteriliyor</h2>
<p class="small" style="margin:6px 0 12px;color:var(--ink)">${MODE_LABEL[r.mode]} anahtarı. Bu sayfadan ayrıldığınızda secret <b>bir daha gösterilmez</b>; sunucuda sadece ondan türetilen imza anahtarı şifreli olarak saklanır. Hemen uygulamanızın <code>.env</code> dosyasına ya da bir şifre yöneticisine kaydedin. Kaybederseniz "Yenile" ile yenisini oluşturun.</p>
<label style="margin:0 0 2px">Site ID</label>${copyLine("rv-pk", r.publicId)}
<label style="margin:0 0 2px">Secret</label>${copyLine("rv-sk", r.secret)}
${envBlock("rv-env", publicUrl, r.publicId, r.secret)}</section>
<script>history.replaceState(null, "", "/site/${esc(slug)}")</script>`;
}

function keyCard(slug: string, mode: KeyMode, key: SiteKey | undefined, manage: boolean, now: number): string {
  const form = (op: string, label: string, cls = "", confirm = "") =>
    `<form class="inline" method="post" action="/site/${esc(slug)}/anahtar/${mode}/${op}"${confirm ? ` onsubmit="return confirm('${confirm}')"` : ""}><button${cls ? ` class="${cls}"` : ""}>${label}</button></form>`;
  if (!key)
    return `<div class="card"><div style="display:flex;justify-content:space-between;gap:8px;align-items:center"><b>${MODE_LABEL[mode]}</b><span class="tag muted">Anahtar yok</span></div>
<p class="small" style="margin:8px 0 12px">${mode === "live" ? "Üretimdeki uygulamanız için. Olayları risk puanına yansır." : "Geliştirme ve deneme için. Olayları akışta TEST etiketiyle görünür, risk puanına yansımaz."}</p>
${manage ? form("olustur", "Anahtar oluştur", "primary") : '<p class="small" style="margin:0">Anahtarı sahip ya da yönetici oluşturabilir.</p>'}</div>`;
  const status = key.lastUsedAt ? `<span class="tag ok">Bağlandı</span>` : `<span class="tag warn">Bekleniyor</span>`;
  return `<div class="card"><div style="display:flex;justify-content:space-between;gap:8px;align-items:center"><b>${MODE_LABEL[mode]}</b>${status}</div>
<label style="margin:10px 0 2px">Site ID</label>${copyLine(`pk-${mode}`, key.publicId)}
<label style="margin:0 0 2px">Secret</label><div class="codeline"><code>sg_${mode}_sk_••••••••${esc(key.secretHint)}</code></div>
<dl class="kv small" style="margin:0 0 12px"><dt>Oluşturuldu</dt><dd>${fmt(key.createdAt.toISOString())}</dd>${key.rotatedAt ? `<dt>Son yenileme</dt><dd>${fmt(key.rotatedAt.toISOString())}</dd>` : ""}
<dt>Son istek</dt><dd>${key.lastUsedAt ? `${ago(key.lastUsedAt.toISOString(), now)}` : "henüz yok"}</dd></dl>
${manage ? `<div class="actions">${form("yenile", "Secret'ı yenile", "", "Eski secret hemen geçersiz olur; uygulamanızdaki SITEGOZCU_SECRET değerini güncellemeniz gerekir. Devam?")}${form("iptal", "İptal et", "danger", "Bu Site ID ve secret kalıcı olarak geçersiz olur. Uygulamanız olay gönderemez. Devam?")}</div>` : ""}</div>`;
}

export function connectionSection(v: ConnView): string {
  const now = Date.now();
  const live = v.keys.find((k) => k.mode === "live");
  const test = v.keys.find((k) => k.mode === "test");
  const status = live?.lastUsedAt
    ? `<span class="tag ok">Bağlandı</span>`
    : live
      ? `<span class="tag warn">Bekleniyor</span>`
      : test?.lastUsedAt
        ? `<span class="tag warn">Sadece test bağlı</span>`
        : `<span class="tag muted">Bağlı değil</span>`;
  const envMode: KeyMode = v.revealed?.mode ?? (live ? "live" : test ? "test" : "live");
  const envKey = envMode === "live" ? live : test;
  const envSecret = v.revealed?.mode === envMode ? v.revealed.secret : "<oluştururken ya da yenilerken gösterilen secret>";
  const base = esc(v.publicUrl);
  return `<section class="card sec" id="baglanti"><header><h2>Bağlantı</h2><span style="display:flex;gap:8px;align-items:center">${v.lastEventAt ? `<span class="count">son olay ${ago(v.lastEventAt, now)}</span>` : ""}${status}</span></header>
<p class="small" style="margin:-4px 0 14px">Web sitenizin ya da API'nizin kendi içinden güvenlik olaylarını (başarısız giriş, şüpheli istek, yetkisiz erişim, uygulama hatası) Site Gözcü'ye göndermesi için. İstekler secret'tan türetilen anahtarla imzalanır; secret ağda gönderilmez.</p>
<div class="keys">${keyCard(v.slug, "live", live, v.manage, now)}${keyCard(v.slug, "test", test, v.manage, now)}</div>
<h3 style="font-size:13px;margin:16px 0 0">.env örneği <span class="small" style="font-weight:400">(${MODE_LABEL[envMode]})</span></h3>
${envBlock("env-ornek", v.publicUrl, envKey?.publicId ?? "<önce anahtar oluşturun>", envSecret)}
<details class="howto"><summary>PHP kurulumu</summary><ol>
<li>İstemciyi sitenizin sunucusuna indirin: <code>curl -o sitegozcu.php ${base}/istemci/sitegozcu.php</code></li>
<li>Yukarıdaki üç satırı uygulamanızın <code>.env</code> dosyasına ya da sunucu ortam değişkenlerine ekleyin.</li>
<li>Kodda kullanın:<pre class="code">require __DIR__ . '/sitegozcu.php';
$gozcu = SiteGozcu::fromEnv(__DIR__ . '/.env');   // ortam değişkenleri tanımlıysa: SiteGozcu::fromEnv()

// Giriş başarısız olunca
$gozcu-&gt;failedLogin($_POST['email'] ?? null);
// Yetkisiz sayfa erişimi
$gozcu-&gt;accessDenied('/yonetim');
// Şüpheli istek (ör. SQL enjeksiyonu denemesi)
$gozcu-&gt;suspiciousRequest('id parametresinde SQL ifadesi');
// Yakalanmayan hatalar
set_exception_handler(function (Throwable $e) use ($gozcu) { $gozcu-&gt;appError($e); throw $e; });</pre></li>
<li>Bağlantıyı test edin: <code>php sitegozcu.php test</code> — bu bölüm "Bağlandı" olur.</li></ol>
<p class="small">PHP 7.4+, ek paket gerekmez. Gönderim 2 saniyede zaman aşımına uğrar ve hata fırlatmaz; Site Gözcü'ye ulaşılamasa da siteniz etkilenmez.</p></details>
<details class="howto"><summary>Node.js kurulumu</summary><ol>
<li>İstemciyi projenize indirin: <code>curl -o sitegozcu.mjs ${base}/istemci/sitegozcu.mjs</code></li>
<li>Yukarıdaki üç satırı <code>.env</code> dosyanıza ekleyin (Node 20.6+: <code>node --env-file=.env app.js</code>).</li>
<li>Kodda kullanın:<pre class="code">import { SiteGozcu } from "./sitegozcu.mjs";
const gozcu = SiteGozcu.fromEnv();

// Giriş başarısız olunca
await gozcu.failedLogin(req.body.email, { ip: req.ip, path: req.path });
// Yetkisiz erişim
gozcu.accessDenied("/yonetim", { ip: req.ip });
// Express hata yakalayıcı
app.use((err, req, res, next) =&gt; { gozcu.appError(err, { path: req.path }); next(err); });</pre></li>
<li>Bağlantıyı test edin: <code>node --env-file=.env sitegozcu.mjs test</code></li></ol>
<p class="small">Node 18+, bağımlılık yok. Hata fırlatmaz; <code>await</code> etmeden de çağırabilirsiniz.</p></details>
<details class="howto"><summary>Diğer diller: imza biçimi</summary>
<p class="small" style="margin:8px 0 0"><code>POST ${base}${INGEST_PATH}</code> · gövde: <code>{"events":[{"type":"auth.failed","actor":"…","ip":"…","path":"…","message":"…"}]}</code> · türler: <code>auth.failed</code>, <code>request.suspicious</code>, <code>access.denied</code>, <code>app.error</code></p>
<pre class="code">k   = HMAC-SHA256(anahtar = SECRET, mesaj = "sitegozcu/v1/signing")
imza = hex(HMAC-SHA256(k, "v1\\n" + zaman + "\\n" + nonce + "\\nPOST\\n${INGEST_PATH}\\n" + hex(SHA256(gövde))))

X-SG-Site: &lt;SITE_ID&gt;
X-SG-Timestamp: &lt;unix saniye&gt;        (sunucu saatiyle en fazla 5 dk fark)
X-SG-Nonce: &lt;16-64 karakter rastgele&gt;   (her istekte yeni)
X-SG-Signature: v1=&lt;imza&gt;</pre></details>
</section>`;
}
