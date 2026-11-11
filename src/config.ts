/**
 * Ortam değişkenlerinden yapılandırma. Gizli değerler (veritabanı, SMTP şifresi, uygulama anahtarı) koda yazılmaz.
 */

export interface Config {
  databaseUrl: string;
  /** Panelin dışarıdan görünen adresi, ör. https://srv1548849.hstgr.cloud — e-posta bağlantıları ve CSRF kontrolü için */
  publicUrl: string;
  port: number;
  /** 2FA sırlarını şifrelemek için ≥32 karakterlik anahtar */
  appSecret: string;
  /** Traefik gibi bir ters vekil arkasında: X-Forwarded-For'dan istemci IP'si okunur */
  trustProxy: boolean;
  /** Sadece yerel test: iç ağ / localhost adresleri izlenebilir */
  allowPrivate: boolean;
  /** Zamanlayıcıyı kapat (testler, CLI) */
  cron: boolean;
  /**
   * Sadece yerel geliştirme: bu bilgisayardan açılınca giriş sorulmaz; DEV_USER (yoksa ilk sahip) olarak oturum açılır.
   * PUBLIC_URL http://127.0.0.1 / localhost değilse uygulama başlamaz — sunucuda açılamaz.
   */
  devNoAuth: boolean;
  devUser: string | null;
  smtp: {
    host: string;
    port: number;
    secure: "tls" | "starttls" | "plain";
    user: string;
    pass: string;
    from: string;
    fromName: string;
  };
}

function req(env: NodeJS.ProcessEnv, key: string): string {
  const v = env[key]?.trim();
  if (!v) throw new Error(`${key} ortam değişkeni tanımlı değil`);
  return v;
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  const appSecret = req(env, "APP_SECRET");
  if (appSecret.length < 32) throw new Error("APP_SECRET en az 32 karakter olmalı (openssl rand -hex 32)");
  const publicUrl = req(env, "PUBLIC_URL").replace(/\/$/, "");
  if (!/^https?:\/\/[^/]+$/.test(publicUrl)) throw new Error("PUBLIC_URL sadece şema + alan adı olmalı, ör. https://panel.ornek.com");
  const devNoAuth = env.DEV_NO_AUTH === "1";
  if (devNoAuth && (!/^http:\/\/(127\.0\.0\.1|localhost)(:\d+)?$/.test(publicUrl) || env.TRUST_PROXY === "1")) {
    throw new Error("DEV_NO_AUTH=1 sadece yerel geliştirmede kullanılabilir (PUBLIC_URL=http://127.0.0.1:<port>, TRUST_PROXY kapalı)");
  }
  return {
    databaseUrl: req(env, "DATABASE_URL"),
    publicUrl,
    port: Number(env.PORT || 3000),
    appSecret,
    trustProxy: env.TRUST_PROXY === "1",
    allowPrivate: env.ALLOW_PRIVATE === "1",
    cron: env.CRON !== "0",
    devNoAuth,
    devUser: env.DEV_USER?.trim() || null,
    smtp: {
      host: env.SMTP_HOST || "smail07.doruk.net.tr",
      port: Number(env.SMTP_PORT || 465),
      secure: (env.SMTP_SECURE || "tls") as Config["smtp"]["secure"],
      user: env.SMTP_USER || "support@arconai.net",
      pass: env.SMTP_PASS || "",
      from: env.SMTP_FROM || env.SMTP_USER || "support@arconai.net",
      fromName: env.SMTP_FROM_NAME || "Site Gözcü",
    },
  };
}
