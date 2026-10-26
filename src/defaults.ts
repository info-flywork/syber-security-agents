/**
 * Her sitede denenen yaygın hassas dosyalar. Platformdan bağımsız: WordPress, PHP, Node, statik…
 * DİKKAT: Çalıştırılabilir dosya (.php, .cgi, .py …) asla eklenmez — HEAD isteği bile onu çalıştırır.
 */
export const COMMON_SENSITIVE_PATHS = [
  // Ortam / kaynak kontrol
  "/.env",
  "/.env.production",
  "/.env.local",
  "/.git/HEAD",
  "/.git/config",
  "/.svn/entries",
  "/.hg/hgrc",
  "/.DS_Store",
  // Editör / FTP ayar dosyaları (FTP şifresi içerir)
  "/.vscode/sftp.json",
  "/sftp-config.json",
  "/.ftpconfig",
  // Yedekler / veritabanı dökümleri
  "/backup.zip",
  "/backup.tar.gz",
  "/backup.sql",
  "/site.zip",
  "/www.zip",
  "/public_html.zip",
  "/db.sql",
  "/dump.sql",
  "/database.sql",
  // Yapılandırma yedekleri
  "/wp-config.php.bak",
  "/wp-config.php~",
  "/wp-config.php.old",
  "/wp-config.php.save",
  "/config.php.bak",
  "/configuration.php.bak",
  // Loglar
  "/error_log",
  "/debug.log",
  "/wp-content/debug.log",
  "/storage/logs/laravel.log",
  // Sunucu
  "/.htpasswd",
  "/server-status",
];

/** Toplam hassas yol sınırı (Workers alt-istek bütçesi için). */
export const MAX_SENSITIVE = 40;
export const MAX_EXTRA_PATHS = 10;
export const MAX_PAGES = 3;

/** Yaygın ve güvenilen dış script kaynakları. */
export const ALLOWED_SCRIPT_HOSTS = [
  "fonts.googleapis.com",
  "fonts.gstatic.com",
  "cdn.jsdelivr.net",
  "cdnjs.cloudflare.com",
  "unpkg.com",
  "code.jquery.com",
  "ajax.googleapis.com",
  "www.googletagmanager.com",
  "www.google-analytics.com",
  "www.google.com",
  "www.gstatic.com",
  "static.cloudflareinsights.com",
  "challenges.cloudflare.com",
  "js.stripe.com",
];

export const DOWN_THRESHOLD = 2;
export const SLOW_MS = 4000;
export const REQUEST_TIMEOUT_MS = 15000;
export const USER_AGENT = "SiteGozcu/1.0 (guvenlik izleme; site sahibinin izniyle)";
export const EXECUTABLE_RE = /\.(php\d?|phtml|phar|cgi|pl|py|sh|asp|aspx|jsp)$/i;
