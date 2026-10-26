/**
 * Hesaplar: organizasyon (müşteri), kullanıcı, üyelik rolleri ve e-posta davetleri.
 */
import { tx, type Db, type Q } from "./db";
import { randomToken, sha256 } from "./security";

export type Role = "owner" | "admin" | "viewer";
export const ROLES: Role[] = ["owner", "admin", "viewer"];
export const ROLE_LABEL: Record<Role, string> = { owner: "Sahip", admin: "Yönetici", viewer: "Görüntüleyen" };

/** Yetki kuralları — sunucu her istekte bunları uygular; arayüz sadece düğmeleri gizler. */
export const can = {
  manageSites: (r: Role) => r !== "viewer",
  invite: (r: Role) => r !== "viewer",
  viewAudit: (r: Role) => r !== "viewer",
  /** Yönetici sahiplere dokunamaz ve kimseyi sahip yapamaz; sahip her şeyi yapabilir. */
  changeMember: (actor: Role, target: Role, next?: Role) => actor === "owner" || (actor === "admin" && target !== "owner" && next !== "owner"),
  inviteAs: (actor: Role, role: Role) => actor === "owner" || (actor === "admin" && role !== "owner"),
};

export const INVITE_TTL_DAYS = 7;
export const LOCK_AFTER_FAILS = 5;
export const LOCK_MINUTES = 15;

export interface User {
  id: string;
  email: string;
  password_hash: string;
  totp_secret: string | null;
  totp_enabled: boolean;
  totp_last_step: string; // bigint
  recovery_codes: string[];
  failed_logins: number;
  locked_until: Date | null;
}

export interface Membership {
  orgId: string;
  orgName: string;
  role: Role;
}

export const normalizeEmail = (e: string) => e.trim().toLowerCase();
export const validEmail = (e: string) => /^[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+$/.test(e) && e.length <= 254;

// ——— Kullanıcılar ———

export async function findUserByEmail(db: Q, email: string): Promise<User | null> {
  const { rows } = await db.query<User>("SELECT * FROM users WHERE email = $1", [normalizeEmail(email)]);
  return rows[0] ?? null;
}

export async function getUser(db: Q, id: string): Promise<User | null> {
  const { rows } = await db.query<User>("SELECT * FROM users WHERE id = $1", [id]);
  return rows[0] ?? null;
}

export async function createUser(db: Q, email: string, passwordHash: string): Promise<User> {
  const { rows } = await db.query<User>("INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING *", [normalizeEmail(email), passwordHash]);
  return rows[0];
}

export async function setPassword(db: Q, userId: string, passwordHash: string): Promise<void> {
  await db.query("UPDATE users SET password_hash = $2, failed_logins = 0, locked_until = NULL WHERE id = $1", [userId, passwordHash]);
}

export const isLocked = (u: User) => !!u.locked_until && u.locked_until.getTime() > Date.now();

/** Hatalı şifre / kod: 5. hatada hesap 15 dakika kilitlenir. */
export async function registerFailure(db: Q, userId: string): Promise<void> {
  await db.query(
    `UPDATE users SET failed_logins = failed_logins + 1,
       locked_until = CASE WHEN failed_logins + 1 >= $2 THEN now() + ($3 || ' minutes')::interval ELSE locked_until END
     WHERE id = $1`,
    [userId, LOCK_AFTER_FAILS, String(LOCK_MINUTES)],
  );
}

export async function registerSuccess(db: Q, userId: string): Promise<void> {
  await db.query("UPDATE users SET failed_logins = 0, locked_until = NULL, last_login_at = now() WHERE id = $1", [userId]);
}

// ——— İki adımlı doğrulama ———

export async function setPendingTotp(db: Q, userId: string, encSecret: string): Promise<void> {
  await db.query("UPDATE users SET totp_secret = $2, totp_enabled = false WHERE id = $1 AND NOT totp_enabled", [userId, encSecret]);
}

export async function enableTotp(db: Q, userId: string, step: number, recoveryHashes: string[]): Promise<void> {
  await db.query("UPDATE users SET totp_enabled = true, totp_last_step = $2, recovery_codes = $3 WHERE id = $1", [userId, step, recoveryHashes]);
}

/** Kod kabul edildi: aynı adımın tekrar kullanılmasını engellemek için kaydedilir (yarış durumuna karşı koşullu). */
export async function recordTotpStep(db: Q, userId: string, step: number): Promise<boolean> {
  const r = await db.query("UPDATE users SET totp_last_step = $2 WHERE id = $1 AND totp_last_step < $2", [userId, step]);
  return (r.rowCount ?? 0) > 0;
}

/** Kurtarma kodu tek kullanımlık: listeden düşülür. */
export async function consumeRecoveryCode(db: Q, userId: string, codeHash: string): Promise<boolean> {
  const r = await db.query("UPDATE users SET recovery_codes = array_remove(recovery_codes, $2) WHERE id = $1 AND $2 = ANY(recovery_codes)", [userId, codeHash]);
  return (r.rowCount ?? 0) > 0;
}

export async function resetTotp(db: Q, userId: string): Promise<void> {
  await db.query("UPDATE users SET totp_secret = NULL, totp_enabled = false, totp_last_step = 0, recovery_codes = '{}' WHERE id = $1", [userId]);
  await db.query("DELETE FROM sessions WHERE user_id = $1", [userId]);
}

// ——— Organizasyonlar ve üyelik ———

export async function createOrg(db: Q, name: string): Promise<string> {
  const { rows } = await db.query<{ id: string }>("INSERT INTO organizations (name) VALUES ($1) RETURNING id", [name.trim().slice(0, 120)]);
  return rows[0].id;
}

export async function listMemberships(db: Q, userId: string): Promise<Membership[]> {
  const { rows } = await db.query<Membership>(
    `SELECT m.org_id AS "orgId", o.name AS "orgName", m.role FROM memberships m JOIN organizations o ON o.id = m.org_id
     WHERE m.user_id = $1 ORDER BY o.name`,
    [userId],
  );
  return rows;
}

export async function getRole(db: Q, userId: string, orgId: string): Promise<Role | null> {
  const { rows } = await db.query<{ role: Role }>("SELECT role FROM memberships WHERE user_id = $1 AND org_id = $2", [userId, orgId]);
  return rows[0]?.role ?? null;
}

export interface Member {
  userId: string;
  email: string;
  role: Role;
  joinedAt: Date;
  lastLoginAt: Date | null;
  totpEnabled: boolean;
}

export async function listMembers(db: Q, orgId: string): Promise<Member[]> {
  const { rows } = await db.query<Member>(
    `SELECT u.id AS "userId", u.email, m.role, m.created_at AS "joinedAt", u.last_login_at AS "lastLoginAt", u.totp_enabled AS "totpEnabled"
     FROM memberships m JOIN users u ON u.id = m.user_id WHERE m.org_id = $1
     ORDER BY CASE m.role WHEN 'owner' THEN 0 WHEN 'admin' THEN 1 ELSE 2 END, u.email`,
    [orgId],
  );
  return rows;
}

/** Rol değiştir / üyeyi çıkar. Organizasyonda en az bir sahip kalmalı. */
export async function changeMember(db: Db, orgId: string, userId: string, next: Role | null): Promise<{ ok: true } | { ok: false; error: string }> {
  return tx(db, async (c) => {
    // Aynı organizasyonda eşzamanlı değişiklikler sırayla işlensin
    await c.query("SELECT id FROM organizations WHERE id = $1 FOR UPDATE", [orgId]);
    const cur = await getRole(c, userId, orgId);
    if (!cur) return { ok: false, error: "Üye bulunamadı" };
    if (cur === "owner" && next !== "owner") {
      const { rows } = await c.query<{ n: number }>("SELECT count(*)::int AS n FROM memberships WHERE org_id = $1 AND role = 'owner'", [orgId]);
      if (rows[0].n <= 1) return { ok: false, error: "Organizasyonda en az bir sahip kalmalı" };
    }
    if (next) await c.query("UPDATE memberships SET role = $3 WHERE org_id = $1 AND user_id = $2", [orgId, userId, next]);
    else {
      await c.query("DELETE FROM memberships WHERE org_id = $1 AND user_id = $2", [orgId, userId]);
      // Çıkarılan kişinin bu organizasyondaki açık oturumları hemen kapanır
      await c.query("DELETE FROM sessions WHERE user_id = $1 AND org_id = $2", [userId, orgId]);
    }
    return { ok: true };
  });
}

// ——— Davetler ———

export interface Invite {
  id: string;
  orgId: string;
  orgName: string;
  email: string;
  role: Role;
  expiresAt: Date;
  invitedByEmail: string | null;
}

/** Yeni davet: aynı e-postaya bekleyen eski davet iptal edilir. Belirteç sadece e-postada bulunur, veritabanında özeti tutulur. */
export async function createInvite(db: Db, orgId: string, email: string, role: Role, invitedBy: string | null): Promise<{ id: string; token: string }> {
  const token = randomToken();
  return tx(db, async (c) => {
    await c.query("UPDATE invites SET revoked_at = now() WHERE org_id = $1 AND email = $2 AND accepted_at IS NULL AND revoked_at IS NULL", [orgId, normalizeEmail(email)]);
    const { rows } = await c.query<{ id: string }>(
      `INSERT INTO invites (org_id, email, role, token_hash, invited_by, expires_at)
       VALUES ($1, $2, $3, $4, $5, now() + ($6 || ' days')::interval) RETURNING id`,
      [orgId, normalizeEmail(email), role, sha256(token), invitedBy, String(INVITE_TTL_DAYS)],
    );
    return { id: rows[0].id, token };
  });
}

const INVITE_SELECT = `SELECT i.id, i.org_id AS "orgId", o.name AS "orgName", i.email, i.role, i.expires_at AS "expiresAt", u.email AS "invitedByEmail"
  FROM invites i JOIN organizations o ON o.id = i.org_id LEFT JOIN users u ON u.id = i.invited_by`;

export async function findInvite(db: Q, token: string): Promise<Invite | null> {
  const { rows } = await db.query<Invite>(`${INVITE_SELECT} WHERE i.token_hash = $1 AND i.accepted_at IS NULL AND i.revoked_at IS NULL AND i.expires_at > now()`, [sha256(token)]);
  return rows[0] ?? null;
}

export async function listPendingInvites(db: Q, orgId: string): Promise<Invite[]> {
  const { rows } = await db.query<Invite>(`${INVITE_SELECT} WHERE i.org_id = $1 AND i.accepted_at IS NULL AND i.revoked_at IS NULL AND i.expires_at > now() ORDER BY i.created_at DESC`, [orgId]);
  return rows;
}

export async function revokeInvite(db: Q, orgId: string, id: string): Promise<Invite | null> {
  const { rows } = await db.query<{ id: string }>("UPDATE invites SET revoked_at = now() WHERE org_id = $1 AND id = $2 AND accepted_at IS NULL AND revoked_at IS NULL RETURNING id", [orgId, id]);
  if (!rows[0]) return null;
  const { rows: inv } = await db.query<Invite>(`${INVITE_SELECT} WHERE i.id = $1`, [id]);
  return inv[0] ?? null;
}

/** Daveti kabul et: tek kullanımlık; zaten üyeyse rol değişmez. */
export async function acceptInvite(db: Db, inviteId: string, userId: string): Promise<boolean> {
  return tx(db, async (c) => {
    const { rows } = await c.query<{ org_id: string; role: Role }>(
      "UPDATE invites SET accepted_at = now() WHERE id = $1 AND accepted_at IS NULL AND revoked_at IS NULL AND expires_at > now() RETURNING org_id, role",
      [inviteId],
    );
    if (!rows[0]) return false;
    await c.query("INSERT INTO memberships (org_id, user_id, role) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING", [rows[0].org_id, userId, rows[0].role]);
    return true;
  });
}
