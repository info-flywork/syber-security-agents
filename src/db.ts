/**
 * PostgreSQL bağlantısı ve şema göçleri. Göçler sırayla, tek seferlik ve kilitli uygulanır.
 */
import pg from "pg";

export type Db = pg.Pool;
export type Q = Pick<pg.PoolClient, "query">;

export function createPool(databaseUrl: string): Db {
  const pool = new pg.Pool({ connectionString: databaseUrl, max: 10, idleTimeoutMillis: 30_000 });
  pool.on("error", (e) => console.error("veritabanı havuz hatası:", e.message));
  return pool;
}

export async function tx<T>(db: Db, fn: (c: pg.PoolClient) => Promise<T>): Promise<T> {
  const c = await db.connect();
  try {
    await c.query("BEGIN");
    const r = await fn(c);
    await c.query("COMMIT");
    return r;
  } catch (e) {
    await c.query("ROLLBACK").catch(() => undefined);
    throw e;
  } finally {
    c.release();
  }
}

const MIGRATIONS: string[] = [
  // 1 — hesaplar, siteler, erişim kaydı
  `
  CREATE TABLE organizations (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name text NOT NULL CHECK (length(name) BETWEEN 1 AND 120),
    created_at timestamptz NOT NULL DEFAULT now()
  );

  CREATE TABLE users (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    email text NOT NULL UNIQUE CHECK (email = lower(email)),
    password_hash text NOT NULL,
    totp_secret text,               -- APP_SECRET ile AES-256-GCM şifreli
    totp_enabled boolean NOT NULL DEFAULT false,
    totp_last_step bigint NOT NULL DEFAULT 0,  -- aynı kodun ikinci kez kullanılmasını engeller
    recovery_codes text[] NOT NULL DEFAULT '{}', -- SHA-256 özetleri
    failed_logins int NOT NULL DEFAULT 0,
    locked_until timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    last_login_at timestamptz
  );

  CREATE TABLE memberships (
    org_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role text NOT NULL CHECK (role IN ('owner', 'admin', 'viewer')),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, user_id)
  );
  CREATE INDEX memberships_user ON memberships(user_id);

  CREATE TABLE invites (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    email text NOT NULL CHECK (email = lower(email)),
    role text NOT NULL CHECK (role IN ('owner', 'admin', 'viewer')),
    token_hash text NOT NULL UNIQUE,
    invited_by uuid REFERENCES users(id) ON DELETE SET NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    accepted_at timestamptz,
    revoked_at timestamptz
  );
  CREATE INDEX invites_org ON invites(org_id);

  CREATE TABLE sessions (
    token_hash text PRIMARY KEY,
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    org_id uuid REFERENCES organizations(id) ON DELETE SET NULL,
    stage text NOT NULL CHECK (stage IN ('totp', 'setup', 'full')),
    created_at timestamptz NOT NULL DEFAULT now(),
    last_seen_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    ip text,
    user_agent text
  );
  CREATE INDEX sessions_user ON sessions(user_id);

  CREATE TABLE sites (
    uuid uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    slug text NOT NULL,
    config jsonb NOT NULL,
    state jsonb,
    lease_until timestamptz,        -- aynı site aynı anda iki kez kontrol edilmesin
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (org_id, slug)
  );

  CREATE TABLE audit_log (
    id bigserial PRIMARY KEY,
    at timestamptz NOT NULL DEFAULT now(),
    org_id uuid REFERENCES organizations(id) ON DELETE CASCADE,
    user_id uuid REFERENCES users(id) ON DELETE SET NULL,
    email text,
    action text NOT NULL,
    target text,
    ip text,
    user_agent text,
    detail jsonb
  );
  CREATE INDEX audit_log_org_at ON audit_log(org_id, at DESC);
  `,
  // 2 — varlık API anahtarları ve uygulamalardan gelen olaylar
  `
  CREATE TABLE site_keys (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    site_uuid uuid NOT NULL REFERENCES sites(uuid) ON DELETE CASCADE,
    mode text NOT NULL CHECK (mode IN ('live', 'test')),
    public_id text NOT NULL UNIQUE,
    signing_key_enc text,           -- secret'tan türetilen imza anahtarı, APP_SECRET ile şifreli; secret'ın kendisi saklanmaz
    secret_hint text NOT NULL,      -- secret'ın son 4 karakteri (hangi anahtar olduğunu tanımak için)
    created_by uuid REFERENCES users(id) ON DELETE SET NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    rotated_at timestamptz,
    revoked_at timestamptz,
    last_used_at timestamptz
  );
  -- Varlık başına mod başına tek etkin anahtar
  CREATE UNIQUE INDEX site_keys_active ON site_keys(site_uuid, mode) WHERE revoked_at IS NULL;

  -- Tekrar oynatma koruması: aynı nonce zaman penceresi içinde ikinci kez kabul edilmez
  CREATE TABLE ingest_nonces (
    key_id uuid NOT NULL REFERENCES site_keys(id) ON DELETE CASCADE,
    nonce text NOT NULL,
    at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (key_id, nonce)
  );
  CREATE INDEX ingest_nonces_at ON ingest_nonces(at);

  CREATE TABLE app_events (
    id bigserial PRIMARY KEY,
    site_uuid uuid NOT NULL REFERENCES sites(uuid) ON DELETE CASCADE,
    key_id uuid REFERENCES site_keys(id) ON DELETE SET NULL,
    mode text NOT NULL CHECK (mode IN ('live', 'test')),
    type text NOT NULL,
    severity text NOT NULL CHECK (severity IN ('critical', 'high', 'info')),
    message text,
    ip text,
    path text,
    actor text,
    meta jsonb,
    occurred_at timestamptz NOT NULL,
    received_at timestamptz NOT NULL DEFAULT now()
  );
  CREATE INDEX app_events_site_time ON app_events(site_uuid, occurred_at DESC);
  `,
];

export async function migrate(db: Db): Promise<void> {
  await tx(db, async (c) => {
    // Aynı anda başlayan iki süreç göçü iki kez uygulamasın
    await c.query("SELECT pg_advisory_xact_lock(7364201)");
    await c.query("CREATE TABLE IF NOT EXISTS schema_migrations (version int PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())");
    const { rows } = await c.query<{ v: number | null }>("SELECT max(version) AS v FROM schema_migrations");
    const current = rows[0]?.v ?? 0;
    for (let i = current; i < MIGRATIONS.length; i++) {
      await c.query(MIGRATIONS[i]);
      await c.query("INSERT INTO schema_migrations (version) VALUES ($1)", [i + 1]);
      console.log(`veritabanı göçü uygulandı: ${i + 1}`);
    }
  });
}
