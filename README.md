# Site Gözcü

**Şirket web sitelerini dışarıdan izleyen güvenlik paneli.** Siteye hiçbir şey kurulmaz. WordPress, PHP, Node, statik site ya da Wix fark etmez. Node.js + PostgreSQL üzerinde çalışır; Docker ile, n8n'in Traefik'inin arkasında yayınlanır. Uyarı e-postaları ARCON'un mail paketiyle gider.

Sunucuya kurulum: **[KURULUM.md](KURULUM.md)**

## Ne kontrol eder

| Kontrol | Uyarı | Örnek |
|---|---|---|
| **Erişim** (ana sayfa + 2 ek sayfa) | 🔴 Art arda 2 kontrolde cevap yoksa | Site çöktü, 5xx hatası |
| **Başka siteye yönlendirme** | 🔴 Hemen | Ele geçirilmiş `.htaccess`, zararlı yönlendirme |
| **Tanınmayan dış kod** | 🟠 Hemen | Sayfaya sonradan eklenen script / iframe (ör. süresi dolup başkasının aldığı bir widget alan adı) |
| **Hassas dosyalar** (32 yaygın ad + siteye özel) | 🔴 Hemen | `.env`, `.git`, `backup.zip`, `wp-config.php.bak`, `.vscode/sftp.json`, `debug.log` … |
| **HTTPS** | 🟠 Hemen | `http://` adresi `https://`'e yönlendirmiyor |
| **DNS** (A / NS / MX) | 🟠 Tek seferlik bildirim | Alan adının sunucusu ya da mail kaydı habersiz değişti |
| **Güvenlik başlıkları** | Sadece panelde, e-posta yok | HSTS, X-Content-Type-Options, clickjacking koruması, sürüm sızıntısı |

- Uyarılar **sadece durum değişince** gider: sorun çıktı ya da düzeldi. Aynı sorun için tekrar tekrar e-posta gelmez.
- Geçici ağ hatası "düzeldi" sayılmaz.
- `.php` gibi çalıştırılabilir dosyalara **asla istek atılmaz**, çünkü istek atmak onları çalıştırır.
- Site eklerken **"sitenin sahibiyim ya da izin aldım"** onayı zorunludur.
- **İç ağ koruması:** Kontrol istekleri bağlantıdan önce alan adının çözüldüğü IP'ye bakar. `127.0.0.1`, `10.x`, `172.16–31.x`, `192.168.x` ve bulut meta veri adresi gibi iç adreslere istek atılmaz. Bu sayede bir alan adı iç ağa çözülse bile aynı sunucudaki n8n'e ya da PostgreSQL'e ulaşılamaz.

## Hesaplar ve yetkiler

- **Organizasyon** = müşteri. Her kullanıcı sadece üyesi olduğu organizasyonların sitelerini, bulgularını ve kayıtlarını görür. Birden fazla organizasyona üye olan kullanıcı menüden organizasyon değiştirir.
- **Roller:**

  | Rol | Yetki |
  |---|---|
  | **Sahip** | Her şey; rolleri ve diğer sahipleri yönetir |
  | **Yönetici** | Siteleri ekler/değiştirir/siler, ekip daveti gönderir, erişim kaydını görür. Sahiplere dokunamaz, kimseyi sahip yapamaz |
  | **Görüntüleyen** | Sadece izler |

  Organizasyonda her zaman en az bir sahip kalır.
- **Kayıt:** Herkese açık kayıt yoktur. İlk sahip komut satırından davet edilir (`create-org`), diğerleri **Ekip** menüsünden e-postayla davet edilir. Davet bağlantısı 7 gün geçerlidir ve bir kez kullanılır.
- **Şifre:** En az 12 karakter. scrypt ile özetlenir (N=2¹⁵, r=8, p=3).
- **İki adımlı doğrulama (zorunlu):** TOTP, 8 tek kullanımlık kurtarma kodu. Aynı kod iki kez kabul edilmez. 2FA sırları veritabanında `APP_SECRET` ile AES-256-GCM şifreli tutulur.
- **Kaba kuvvet koruması:** 5 hatalı şifre ya da kod denemesinde hesap 15 dakika kilitlenir. IP başına 15 dakikada en fazla 20 giriş denemesi yapılabilir.
- **Oturum:** Rastgele belirteç; veritabanında sadece SHA-256 özeti tutulur. 12 saat işlem yapılmazsa ya da en geç 7 günde kapanır. Şifre değişince diğer cihazlardaki oturumlar kapanır. Çerez `HttpOnly`, `SameSite=Lax`, HTTPS'te `__Host-` önekli ve `Secure`. Form istekleri ayrıca Origin kontrolüyle korunur (CSRF).
- **Erişim kaydı:** Girişler, hatalı denemeler, 2FA, davetler, rol değişiklikleri, site işlemleri ve yetkisiz işlem denemeleri; kim, ne zaman, hangi IP ve tarayıcıdan yaptı. Sahip ve yöneticiler panelde görür. Kayıtlar 1 yıl saklanır.

## Uygulama bağlantısı (API anahtarları)

Web sitenizin ya da API'nizin kendi içinden güvenlik olaylarını panele göndermesi için. Varlık sayfasındaki **Bağlantı** bölümünden yönetilir.

- **Anahtarlar:** Her varlık için bir **canlı (live)** ve bir **test** anahtarı oluşturulabilir.
  - Site ID (`sg_live_pk_…`) açıktır.
  - Secret (`sg_live_sk_…`) **sadece oluşturulduğu ya da yenilendiği anda bir kez** gösterilir.
  - Test anahtarının olayları akışta `TEST` etiketiyle görünür, risk puanına yansımaz.
- **Saklama:** Secret veritabanında tutulmaz. Sunucu sadece secret'tan tek yönlü türetilen imza anahtarını (`HMAC-SHA256(secret, "sitegozcu/v1/signing")`) saklar; o da `APP_SECRET` ile AES-256-GCM şifrelidir. Sahte olay yazmak için hem veritabanı hem `APP_SECRET` ele geçirilmelidir.
- **Yenile / İptal:**
  - **Secret'ı yenile:** Site ID aynı kalır, eski secret anında geçersiz olur.
  - **İptal et:** Site ID kalıcı olarak kapanır.
  - Bu işlemleri sahip ve yönetici yapar; görüntüleyen sadece Site ID'yi ve durumu görür.
- **Durum:**
  - **Bağlandı:** Canlı anahtarla en az bir geçerli istek geldi.
  - **Bekleniyor:** Anahtar var ama henüz istek gelmedi.
  - Son olay zamanı da gösterilir.
- **`POST /api/v1/events`:**
  - İstek HMAC-SHA256 ile imzalanır; secret ağda gönderilmez.
  - Zaman damgası sunucu saatinden en fazla **5 dakika** farklı olabilir. Aynı nonce ikinci kez kabul edilmez (tekrar oynatma koruması).
  - Olay her zaman **anahtarın kendi varlığına** yazılır; gövdede başka bir varlık seçilemez.
  - İstek sınırı: anahtar başına dakikada 120, IP başına dakikada 300 istek; istek başına en fazla 50 olay.
- **Olay türleri:**

  | Tür | Varsayılan önem | Risk katkısı |
  |---|---|---|
  | `auth.failed` — başarısız giriş | Öneri | 0,5 |
  | `request.suspicious` — şüpheli istek | Yüksek | 5 |
  | `access.denied` — yetkisiz erişim denemesi | Yüksek | 5 |
  | `app.error` — uygulama hatası | Öneri | 0,5 |

  Önem istekte `info`, `high` ya da `critical` (15 puan) olarak değiştirilebilir. Son 24 saatin canlı olayları toplanır; varlık başına en fazla 50 puan eklenir. Olaylar 30 gün saklanır.
- **İstemciler:** Tek dosyadır ve bağımlılık gerektirmez. Panelden indirilir: `/istemci/sitegozcu.php` (PHP 7.4+) ve `/istemci/sitegozcu.mjs` (Node 18+). İkisi de hata fırlatmaz ve 2 saniyede zaman aşımına uğrar; panele ulaşılamasa da uygulama etkilenmez. `php sitegozcu.php test` ya da `node --env-file=.env sitegozcu.mjs test` bağlantıyı dener.

```
SITEGOZCU_URL=https://srv1548849.hstgr.cloud
SITEGOZCU_SITE_ID=sg_live_pk_…
SITEGOZCU_SECRET=sg_live_sk_…
```

## Panel

Site sayfasındaki butonlar (Sahip ve Yönetici):

| Buton | Ne yapar |
|---|---|
| Şimdi kontrol et | Sırasını beklemeden kontrol eder |
| Duraklat / Devam ettir | Bakım sırasında yanlış alarm gelmesini önler |
| Script referansını sıfırla | Siteye bilerek yeni bir dış servis eklediyseniz (analitik, sohbet widget'ı vb.) mevcut kaynakları yeniden "bilinen" kabul eder |
| Ayarlar | E-posta, sayfalar, siteye özel hassas dosyalar, sıklık |

Sınır: organizasyon başına en fazla 40 site, site başına en fazla 40 dosya kontrolü.

## Yerel geliştirme

```bash
npm install
npm run db:dev                       # Docker'da geçici PostgreSQL (127.0.0.1:55432)
cp .env.example .env                 # PUBLIC_URL=http://127.0.0.1:3100, PORT=3100, APP_SECRET, DATABASE_URL
npm run cli -- create-org "Deneme" ben@ornek.com   # davet bağlantısını açın
npm run dev                          # http://127.0.0.1:3100
```

Yerel `DATABASE_URL`: `postgres://sitegozcu:yerel-gelistirme@127.0.0.1:55432/sitegozcu`. SMTP tanımlı değilse davet bağlantıları sunucu loguna yazılır.

```bash
npm test             # birim testleri
npm run typecheck
# Uçtan uca (gerçek PostgreSQL; test veritabanı her çalıştırmada SIFIRLANIR; PHP kuruluysa PHP istemcisi de denenir):
docker exec site-gozcu-dev-db createdb -U sitegozcu sitegozcu_test
TEST_DATABASE_URL=postgres://sitegozcu:yerel-gelistirme@127.0.0.1:55432/sitegozcu_test npm test
```

| Dosya | İçerik |
|---|---|
| `src/checks.ts`, `src/incidents.ts`, `src/alert.ts` | Kontroller, olay durumu, uyarı e-postası (Cloudflare sürümünden aynen) |
| `src/defaults.ts`, `src/plan.ts`, `src/site-input.ts` | Hassas dosya listesi, eşikler, site formu doğrulaması |
| `src/monitor.ts` | Site kontrol akışı (eski Durable Object ajanının karşılığı) |
| `src/sites.ts` | Site deposu (PostgreSQL, organizasyona göre sınırlı) |
| `src/accounts.ts`, `src/auth.ts`, `src/security.ts` | Hesaplar ve roller, oturumlar, şifre / TOTP / şifreleme |
| `src/audit.ts` | Erişim kaydı |
| `src/app.ts`, `src/server.ts` | HTTP yönlendirici, Node sunucusu + node-cron zamanlayıcı |
| `src/ui.ts`, `src/ui-account.ts` | Panel ve hesap ekranları |
| `src/net.ts`, `src/mail.ts`, `src/smtp.ts` | İç ağ korumalı fetch, e-posta |
| `src/apikeys.ts`, `src/ingest.ts`, `src/app-events.ts`, `src/ui-connect.ts` | API anahtarları ve imza, olay alma API'si, uygulama olayları, Bağlantı bölümü |
| `clients/php/sitegozcu.php`, `clients/node/sitegozcu.mjs` | Tek dosyalık istemciler |
| `src/db.ts`, `src/cli.ts`, `src/config.ts` | Şema göçleri, yönetim komutları, ortam değişkenleri |
