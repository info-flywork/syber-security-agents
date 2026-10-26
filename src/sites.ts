/**
 * Site deposu (PostgreSQL). Her sorgu organizasyon kimliğiyle sınırlanır: bir kullanıcı başka
 * organizasyonun sitesini adresini bilse bile göremez ya da değiştiremez.
 */
import type { Db, Q } from "./db";
import type { SiteConfig, SiteState } from "./types";

export const MAX_SITES_PER_ORG = 40;

export interface SiteRow {
  uuid: string;
  orgId: string;
  site: SiteConfig;
  st: SiteState | null;
}

type Raw = { uuid: string; org_id: string; config: SiteConfig; state: SiteState | null };
const toRow = (r: Raw): SiteRow => ({ uuid: r.uuid, orgId: r.org_id, site: r.config, st: r.state });

export async function listSites(db: Q, orgId: string): Promise<SiteRow[]> {
  const { rows } = await db.query<Raw>("SELECT uuid, org_id, config, state FROM sites WHERE org_id = $1", [orgId]);
  return rows.map(toRow).sort((a, b) => a.site.name.localeCompare(b.site.name, "tr"));
}

export async function getSite(db: Q, orgId: string, slug: string): Promise<SiteRow | null> {
  const { rows } = await db.query<Raw>("SELECT uuid, org_id, config, state FROM sites WHERE org_id = $1 AND slug = $2", [orgId, slug]);
  return rows[0] ? toRow(rows[0]) : null;
}

export async function addSite(db: Db, orgId: string, site: SiteConfig): Promise<{ ok: true; row: SiteRow } | { ok: false; error: string }> {
  const { rows: cnt } = await db.query<{ n: number }>("SELECT count(*)::int AS n FROM sites WHERE org_id = $1", [orgId]);
  if (cnt[0].n >= MAX_SITES_PER_ORG) return { ok: false, error: `En fazla ${MAX_SITES_PER_ORG} site izlenebilir` };
  const { rows } = await db.query<Raw>(
    "INSERT INTO sites (org_id, slug, config) VALUES ($1, $2, $3) ON CONFLICT (org_id, slug) DO NOTHING RETURNING uuid, org_id, config, state",
    [orgId, site.id, site],
  );
  if (!rows[0]) return { ok: false, error: `${site.origin} zaten listede` };
  return { ok: true, row: toRow(rows[0]) };
}

export async function updateSite(
  db: Q,
  orgId: string,
  slug: string,
  patch: Partial<Pick<SiteConfig, "name" | "emails" | "pages" | "extraPaths" | "intervalMin" | "paused">>,
): Promise<SiteConfig | null> {
  const { rows } = await db.query<{ config: SiteConfig }>(
    "UPDATE sites SET config = config || $3::jsonb WHERE org_id = $1 AND slug = $2 RETURNING config",
    [orgId, slug, JSON.stringify(patch)],
  );
  return rows[0]?.config ?? null;
}

export async function removeSite(db: Q, orgId: string, slug: string): Promise<boolean> {
  const r = await db.query("DELETE FROM sites WHERE org_id = $1 AND slug = $2", [orgId, slug]);
  return (r.rowCount ?? 0) > 0;
}

export async function saveState(db: Q, uuid: string, state: SiteState | null): Promise<void> {
  await db.query("UPDATE sites SET state = $2 WHERE uuid = $1", [uuid, state]);
}

/** Kontrol kilidi: süresi dolmuş ya da boşsa alınır ve en güncel durum döner. Çöken süreç kilidi 10 dk sonra bırakır. */
export async function claimLease(db: Q, uuid: string): Promise<SiteRow | null> {
  const { rows } = await db.query<Raw>(
    `UPDATE sites SET lease_until = now() + interval '10 minutes'
     WHERE uuid = $1 AND (lease_until IS NULL OR lease_until < now())
     RETURNING uuid, org_id, config, state`,
    [uuid],
  );
  return rows[0] ? toRow(rows[0]) : null;
}

export async function releaseLease(db: Q, uuid: string): Promise<void> {
  await db.query("UPDATE sites SET lease_until = NULL WHERE uuid = $1", [uuid]);
}

/** Zamanlayıcı için: tüm organizasyonlardaki duraklatılmamış siteler. */
export async function listActiveSites(db: Q): Promise<SiteRow[]> {
  const { rows } = await db.query<Raw>("SELECT uuid, org_id, config, state FROM sites WHERE NOT (config->>'paused')::boolean");
  return rows.map(toRow);
}
