# Sunucu kurulumu — srv1548849.hstgr.cloud

Site Gözcü, sunucuda n8n'in kullandığı **Traefik**'in arkasında Docker konteyneri olarak çalışır. SSL sertifikasını Traefik Let's Encrypt'ten alır. Veritabanı olarak sunucuda zaten çalışan **PostgreSQL** (`127.0.0.1:5432`, veritabanı ve kullanıcı `sitegozcu`) kullanılır. Uygulama dışarıya port açmaz; trafik sadece Traefik'ten gelir.

Komutlar sunucuda `root` olarak çalıştırılır (`ssh root@srv1548849.hstgr.cloud`). `<…>` ile gösterilen yerler sizin değerlerinizdir.

---

## 1. Mevcut kurulumu tanıyın (5 dk)

### 1a. Traefik'in ağı, sertifika çözücüsü ve n8n'in alan adı

```bash
docker ps --format 'table {{.Names}}\t{{.Image}}\t{{.Ports}}'
```

Listede Traefik ve n8n konteynerlerinin adlarını bulun (ör. `root-traefik-1`, `root-n8n-1`). Sonra:

```bash
TRAEFIK=<traefik-konteyner-adı>
N8N=<n8n-konteyner-adı>

# Traefik'in bağlı olduğu Docker ağı → .env içindeki TRAEFIK_NETWORK
docker inspect -f '{{range $k, $v := .NetworkSettings.Networks}}{{$k}}{{"\n"}}{{end}}' $TRAEFIK

# Sertifika çözücüsünün adı → CERT_RESOLVER (ör. mytlschallenge)
docker inspect $TRAEFIK | grep -o 'certificatesresolvers\.[A-Za-z0-9_-]*' | sort -u

# HTTPS giriş noktasının adı → TRAEFIK_ENTRYPOINT (genelde websecure)
docker inspect $TRAEFIK | grep -o 'entrypoints\.[A-Za-z0-9_-]*\.address' | sort -u

# n8n hangi alan adında yayında?
docker inspect $N8N | grep -o 'Host(`[^`]*`)' | sort -u
```

> **Alan adı çakışması:** n8n `srv1548849.hstgr.cloud` adresinin **kendisinde** yayındaysa Site Gözcü aynı adı kullanamaz. O durumda bir alt alan adı seçin, ör. `gozcu.srv1548849.hstgr.cloud`, ve önce çözüldüğünü doğrulayın: `getent hosts gozcu.srv1548849.hstgr.cloud`. Sunucunun IP'si dönmüyorsa Hostinger panelinden DNS kaydı eklemek gerekir. n8n `n8n.srv1548849.hstgr.cloud` gibi bir alt alan adındaysa ana ad boştur ve doğrudan kullanılabilir.

### 1b. PostgreSQL nasıl çalışıyor?

```bash
ss -ltnp | grep 5432
psql --version 2>/dev/null; docker ps --filter publish=5432 --format '{{.Names}}'
```

- Çıktıda süreç adı **`postgres`** ise PostgreSQL doğrudan sunucuda (systemd) çalışıyordur → **2A**'yı izleyin.
- Süreç adı **`docker-proxy`** ise PostgreSQL bir konteynerde çalışıyordur → **2B**'yi izleyin.

PostgreSQL sürümü **13 veya üstü** olmalı.

---

## 2A. PostgreSQL sunucuda çalışıyorsa: konteynerden erişim

Konteynerler sunucunun `127.0.0.1` adresine erişemez. Erişimi Docker köprüsünün ağ geçidi (genelde `172.17.0.1`) üzerinden açacağız. Bu adres internete açık değildir.

```bash
# Docker köprüsünün ağ geçidi (host.docker.internal bu adrese gider)
docker network inspect bridge -f '{{(index .IPAM.Config 0).Gateway}}'      # ör. 172.17.0.1
# Traefik ağının alt ağı (uygulamanın bağlantıları bu aralıktan gelir)
docker network inspect <TRAEFIK_NETWORK> -f '{{(index .IPAM.Config 0).Subnet}}'   # ör. 172.18.0.0/16

sudo -u postgres psql -tAc "SHOW config_file"   # postgresql.conf yolu
sudo -u postgres psql -tAc "SHOW hba_file"      # pg_hba.conf yolu
```

1. **`postgresql.conf`** dosyasında `listen_addresses` satırını bulun ve ağ geçidini ekleyin:

   ```
   listen_addresses = 'localhost,172.17.0.1'
   ```

2. **`pg_hba.conf`** dosyasının sonuna şu satırı ekleyin. Traefik ağının alt ağı `172.16.0.0/12` aralığında değilse (ör. `192.168.x.x`) o aralığı yazın.

   ```
   host  sitegozcu  sitegozcu  172.16.0.0/12  scram-sha-256
   ```

3. PostgreSQL'i yeniden başlatın ve sadece iç adreslerde dinlediğini doğrulayın:

   ```bash
   systemctl restart postgresql
   ss -ltn | grep 5432      # sadece 127.0.0.1 ve 172.17.0.1 görünmeli, 0.0.0.0 OLMAMALI
   ```

4. Güvenlik duvarı (UFW) açıksa konteynerlerin erişimine izin verin. Bu kural internete port açmaz.

   ```bash
   ufw status | head -1
   ufw allow from 172.16.0.0/12 to 172.17.0.1 port 5432 proto tcp
   ```

5. Kullanıcının şemada tablo oluşturabildiğinden emin olun (PostgreSQL 15+ için gerekli):

   ```bash
   sudo -u postgres psql -c "ALTER DATABASE sitegozcu OWNER TO sitegozcu;"
   sudo -u postgres psql -d sitegozcu -c "ALTER SCHEMA public OWNER TO sitegozcu;"
   ```

   `sitegozcu` kullanıcısının şifresini bilmiyorsanız yenisini belirleyin: `sudo -u postgres psql -c "\password sitegozcu"`. Şifrede `$`, `@`, `:`, `/` ve `#` karakterlerini kullanmayın; `openssl rand -hex 24` uygun bir şifre üretir.

`.env` içindeki bağlantı:

```
DATABASE_URL=postgres://sitegozcu:<şifre>@host.docker.internal:5432/sitegozcu
```

## 2B. PostgreSQL bir konteynerde çalışıyorsa

```bash
PG=<postgres-konteyner-adı>
docker inspect -f '{{range $k, $v := .NetworkSettings.Networks}}{{$k}}{{"\n"}}{{end}}' $PG
```

Site Gözcü'yü bu ağa da bağlayın. Proje klasöründe `docker-compose.override.yml` oluşturun:

```yaml
services:
  app:
    networks: [traefik, pg]
networks:
  pg:
    external: true
    name: <postgres-ağının-adı>
```

`.env` içindeki bağlantı, konteyner adıyla:

```
DATABASE_URL=postgres://sitegozcu:<şifre>@<postgres-konteyner-adı>:5432/sitegozcu
```

2A'daki `listen_addresses`, `pg_hba` ve UFW adımlarına bu durumda gerek yoktur. Postgres imajının varsayılan `pg_hba` ayarı Docker ağından şifreyle bağlantıya izin verir.

---

## 3. Dosyaları sunucuya kopyalayın

Mac'teki terminalden:

```bash
rsync -av --delete --exclude node_modules --exclude dist --exclude .env --exclude '.dev.vars*' --exclude .git ~/Desktop/site-gozcu/ root@srv1548849.hstgr.cloud:/opt/site-gozcu/
```

## 4. `.env` dosyasını oluşturun

Sunucuda:

```bash
cd /opt/site-gozcu
cp .env.example .env && chmod 600 .env
openssl rand -hex 32        # çıktıyı APP_SECRET'a yazın
nano .env
```

Doldurulacaklar:

| Değişken | Değer |
|---|---|
| `PUBLIC_URL` | `https://srv1548849.hstgr.cloud` (1a'da alt alan adı seçtiyseniz o) |
| `DOMAIN` | Aynı alan adı, `https://` olmadan |
| `APP_SECRET` | `openssl rand -hex 32` çıktısı. **Bir şifre yöneticisine yedekleyin.** Kaybolursa herkesin 2FA'sı sıfırlanmak zorunda kalır. |
| `DATABASE_URL` | 2A ya da 2B'deki bağlantı |
| `SMTP_PASS` | `support@arconai.net` e-posta şifresi |
| `TRAEFIK_NETWORK` | 1a'daki ağ adı |
| `CERT_RESOLVER` | 1a'daki çözücü adı |
| `TRAEFIK_ENTRYPOINT` | 1a'daki giriş noktası (genelde `websecure`) |

> `ALLOW_PRIVATE=1` satırını sunucuda **asla** açmayın. Bu ayar iç ağ koruması olan SSRF engelini kapatır.

## 5. Başlatın

```bash
cd /opt/site-gozcu
docker compose up -d --build
docker compose logs -f app
```

Logda şu iki satırı görmelisiniz (`Ctrl+C` ile çıkın):

```
veritabanı göçü uygulandı: 1
Site Gözcü dinliyor: :3000 · https://srv1548849.hstgr.cloud
```

Sertifika ilk açılışta 10–60 saniyede alınır. Kontrol:

```bash
curl -sI https://srv1548849.hstgr.cloud/login | head -1     # HTTP/2 200
docker compose ps                                           # STATUS: healthy
```

## 6. İlk organizasyonu ve sahibini oluşturun

Panelde herkese açık kayıt yoktur. Organizasyonlar komut satırından açılır:

```bash
docker compose exec app node dist/cli.js create-org "ARCON" yazilim@fly-work.com
```

Komut bir davet bağlantısı yazdırır ve `SMTP_PASS` tanımlıysa bağlantıyı e-postayla da gönderir. Bağlantıyı açın, sırasıyla:

1. Şifre belirleyin (en az 12 karakter).
2. İki adımlı doğrulamayı kurun: QR kodu Google/Microsoft Authenticator, 1Password ya da Bitwarden ile tarayın.
3. **Kurtarma kodlarını** bir şifre yöneticisine kaydedin; bu sayfa bir daha gösterilmez.

Sonrasında **Ekip** menüsünden ekip arkadaşlarınızı e-postayla davet edin. Her müşteri için ayrı bir organizasyon açabilirsiniz; her kullanıcı sadece üyesi olduğu organizasyonun varlıklarını görür.

## 7. Siteleri ekleyin

Panelde **Site ekle** menüsünü açın, sonra her site sayfasında **Test e-postası** ile uyarı e-postasının geldiğini doğrulayın. Kontroller 5 dakikada bir, her sitenin kendi sıklığına göre çalışır.

---

## Güncelleme

Mac'ten 3. adımdaki `rsync` komutunu tekrar çalıştırın, sonra sunucuda:

```bash
cd /opt/site-gozcu && docker compose up -d --build
```

Veritabanı göçleri açılışta kendiliğinden uygulanır.

## Yedekleme

Veritabanını her gece yedekleyin:

```bash
mkdir -p /root/yedek && chmod 700 /root/yedek
crontab -e
```

Açılan dosyaya şu satırı ekleyin. 2A kurulumunda:

```
30 3 * * * sudo -u postgres pg_dump sitegozcu | gzip > /root/yedek/sitegozcu-$(date +\%F).sql.gz && find /root/yedek -name 'sitegozcu-*' -mtime +14 -delete
```

2B kurulumunda `sudo -u postgres pg_dump` yerine `docker exec <postgres-konteyner-adı> pg_dump -U sitegozcu` yazın.

`.env` dosyası (özellikle `APP_SECRET`) yedeğin parçasıdır. Onu veritabanı yedeğinden **ayrı** ve güvenli bir yerde saklayın.

## Yönetim komutları

```bash
docker compose exec app node dist/cli.js list-orgs
docker compose exec app node dist/cli.js invite <organizasyon-id> <e-posta> <owner|admin|viewer>
docker compose exec app node dist/cli.js reset-2fa <e-posta>        # telefonunu kaybeden kullanıcı
docker compose exec app node dist/cli.js reset-password <e-posta>   # geçici şifre üretir
docker compose exec app node dist/cli.js unlock <e-posta>           # 5 hatalı denemede 15 dk kilit
```

## Sorun giderme

| Belirti | Neden / çözüm |
|---|---|
| Log: `ECONNREFUSED … host.docker.internal:5432` | PostgreSQL ağ geçidinde dinlemiyor ya da UFW engelliyor → 2A adım 1, 3, 4 |
| Log: `no pg_hba.conf entry for host "172.…"` | `pg_hba.conf` satırındaki aralık Traefik ağını kapsamıyor → 2A adım 2 |
| Log: `password authentication failed` | `DATABASE_URL` şifresi yanlış ya da özel karakter içeriyor |
| Log: `permission denied for schema public` | 2A adım 5 |
| Tarayıcıda Traefik `404 page not found` | `TRAEFIK_NETWORK` yanlış ya da `DOMAIN` farklı → `docker compose config` çıktısındaki etiketleri kontrol edin |
| Sertifika hatası / "TRAEFIK DEFAULT CERT" | `CERT_RESOLVER` adı yanlış ya da alan adı sunucuya çözülmüyor → `docker logs $TRAEFIK 2>&1 \| grep -i acme` |
| POST'larda "Geçersiz istek kaynağı" | `PUBLIC_URL` tarayıcıdaki adresle birebir aynı değil (http/https, alt alan adı) |

## Eski Cloudflare kurulumu

Site Gözcü daha önce `wrangler deploy` ile Cloudflare'e yüklendiyse oradaki eski sürüm çalışmaya ve e-posta göndermeye devam eder. Yeni sunucu çalıştıktan sonra Cloudflare panelinden **Workers & Pages → site-gozcu → Settings → Delete** ile kaldırın. Eski sitelerin listesi taşınmaz; siteleri panelden yeniden ekleyin.
