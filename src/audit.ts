/**
 * Erişim kaydı: girişler, başarısız denemeler, 2FA, ekip ve site işlemleri. Kim, ne zaman, hangi IP'den.
 */
import type { Q } from "./db";

export interface AuditEntry {
  orgId?: string | null;
  userId?: string | null;
  email?: string | null;
  action: string;
  target?: string | null;
  ip?: string | null;
  userAgent?: string | null;
  detail?: Record<string, unknown> | null;
}

export interface AuditRow {
  at: Date;
  email: string | null;
  action: string;
  target: string | null;
  ip: string | null;
  userAgent: string | null;
  detail: Record<string, unknown> | null;
}

export const AUDIT_LABEL: Record<string, string> = {
  "login.ok": "Giriş yaptı",
  "login.fail": "Hatalı şifre",
  "login.locked": "Kilitli hesaba giriş denemesi",
  "login.unknown": "Kayıtlı olmayan e-postayla giriş denemesi",
  "totp.ok": "İki adımlı doğrulama başarılı",
  "totp.fail": "Hatalı doğrulama kodu",
  "totp.recovery": "Kurtarma koduyla giriş",
  "totp.enabled": "İki adımlı doğrulamayı kurdu",
  logout: "Çıkış yaptı",
  "password.changed": "Şifresini değiştirdi",
  "invite.sent": "Davet gönderdi",
  "invite.revoked": "Daveti iptal etti",
  "invite.accepted": "Daveti kabul etti",
  "member.role": "Rol değiştirdi",
  "member.removed": "Üyeyi çıkardı",
  "org.switch": "Organizasyon değiştirdi",
  "site.add": "Site ekledi",
  "site.edit": "Site ayarlarını değiştirdi",
  "site.delete": "Site sildi",
  "site.run": "Elle kontrol başlattı",
  "site.pause": "İzlemeyi duraklattı",
  "site.resume": "İzlemeyi sürdürdü",
  "site.reset": "Script referansını sıfırladı",
  "site.test-mail": "Test e-postası gönderdi",
  "site.view": "Site sayfasını görüntüledi",
  "audit.view": "Erişim kaydını görüntüledi",
  "access.denied": "Yetkisiz işlem denemesi",
};

export async function audit(db: Q, e: AuditEntry): Promise<void> {
  try {
    await db.query("INSERT INTO audit_log (org_id, user_id, email, action, target, ip, user_agent, detail) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)", [
      e.orgId ?? null,
      e.userId ?? null,
      e.email ?? null,
      e.action,
      e.target ?? null,
      e.ip ?? null,
      e.userAgent?.slice(0, 300) ?? null,
      e.detail ?? null,
    ]);
  } catch (err) {
    // Kayıt yazılamadı diye kullanıcının işlemi bozulmasın; ama mutlaka loga düşsün
    console.error("erişim kaydı yazılamadı:", (err as Error).message, e.action);
  }
}

/** Organizasyonun kayıtları + organizasyon seçilmeden önce üyeleri hakkında yazılanlar (ör. hatalı giriş denemeleri). */
export async function listAudit(db: Q, orgId: string, limit = 300): Promise<AuditRow[]> {
  const { rows } = await db.query<AuditRow>(
    `SELECT at, email, action, target, ip, user_agent AS "userAgent", detail FROM audit_log
     WHERE org_id = $1 OR (org_id IS NULL AND user_id IN (SELECT user_id FROM memberships WHERE org_id = $1))
     ORDER BY at DESC LIMIT $2`,
    [orgId, limit],
  );
  return rows;
}

/** 1 yıldan eski kayıtları ve süresi dolmuş oturumları temizle (günde bir). */
export async function pruneOld(db: Q): Promise<void> {
  await db.query("DELETE FROM audit_log WHERE at < now() - interval '365 days'");
  await db.query("DELETE FROM sessions WHERE expires_at < now()");
  await db.query("DELETE FROM invites WHERE expires_at < now() - interval '30 days'");
}
