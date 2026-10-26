/**
 * Yönetim komutları (sunucuda: docker compose exec app node dist/cli.js <komut>).
 * Panelde herkese açık kayıt yok: organizasyonlar buradan açılır, sahibi davetle hesabını kurar.
 */
import { createInvite, createOrg, findUserByEmail, normalizeEmail, resetTotp, setPassword, validEmail } from "./accounts";
import { loadConfig } from "./config";
import { createPool, migrate } from "./db";
import { createMailer, smtpReady } from "./mail";
import { hashPassword, randomToken } from "./security";

const HELP = `Kullanım:
  create-org "<organizasyon adı>" <sahip-e-postası>   Organizasyon açar, sahibine davet bağlantısı üretir
  invite <organizasyon-id> <e-posta> <owner|admin|viewer>   Organizasyona davet bağlantısı üretir
  list-orgs                                          Organizasyonları ve üye sayılarını listeler
  reset-2fa <e-posta>                                İki adımlı doğrulamayı sıfırlar (sonraki girişte yeniden kurulur)
  reset-password <e-posta>                           Geçici şifre üretir, tüm oturumları kapatır
  unlock <e-posta>                                   Hatalı denemeler nedeniyle kilitlenen hesabı açar`;

async function main(): Promise<void> {
  const [cmd, ...args] = process.argv.slice(2);
  if (!cmd || cmd === "help" || cmd === "--help") {
    console.log(HELP);
    return;
  }
  const cfg = loadConfig();
  const db = createPool(cfg.databaseUrl);
  try {
    await migrate(db);
    const user = async (email: string) => {
      const u = await findUserByEmail(db, email ?? "");
      if (!u) throw new Error(`Kullanıcı bulunamadı: ${email}`);
      return u;
    };
    const sendInvite = async (orgId: string, orgName: string, email: string, role: "owner" | "admin" | "viewer") => {
      const { token } = await createInvite(db, orgId, email, role, null);
      const link = `${cfg.publicUrl}/davet/${token}`;
      console.log(`Davet bağlantısı (7 gün geçerli, tek kullanımlık):\n  ${link}`);
      if (smtpReady(cfg)) {
        await createMailer(cfg)([email], `${orgName} — Site Gözcü daveti`, `<p>${orgName} organizasyonu için Site Gözcü hesabınızı kurun:</p><p><a href="${link}">${link}</a></p><p>Bağlantı 7 gün geçerlidir.</p>`);
        console.log(`Davet e-postası gönderildi: ${email}`);
      }
    };

    switch (cmd) {
      case "create-org": {
        const [name, email] = args;
        if (!name || !email || !validEmail(normalizeEmail(email))) throw new Error('Kullanım: create-org "<ad>" <e-posta>');
        const id = await createOrg(db, name);
        console.log(`Organizasyon açıldı: ${name} (${id})`);
        await sendInvite(id, name, normalizeEmail(email), "owner");
        break;
      }
      case "invite": {
        const [orgId, email, role] = args;
        if (!["owner", "admin", "viewer"].includes(role) || !validEmail(normalizeEmail(email ?? ""))) throw new Error("Kullanım: invite <organizasyon-id> <e-posta> <owner|admin|viewer>");
        const { rows } = await db.query<{ name: string }>("SELECT name FROM organizations WHERE id = $1", [orgId]);
        if (!rows[0]) throw new Error("Organizasyon bulunamadı");
        await sendInvite(orgId, rows[0].name, normalizeEmail(email), role as "owner");
        break;
      }
      case "list-orgs": {
        const { rows } = await db.query<{ id: string; name: string; members: number; sites: number }>(
          `SELECT o.id, o.name, (SELECT count(*)::int FROM memberships m WHERE m.org_id = o.id) AS members,
                  (SELECT count(*)::int FROM sites s WHERE s.org_id = o.id) AS sites FROM organizations o ORDER BY o.created_at`,
        );
        for (const r of rows) console.log(`${r.id}  ${r.name}  · ${r.members} üye · ${r.sites} site`);
        if (!rows.length) console.log("Henüz organizasyon yok.");
        break;
      }
      case "reset-2fa": {
        const u = await user(args[0]);
        await resetTotp(db, u.id);
        console.log(`${u.email}: iki adımlı doğrulama sıfırlandı, oturumları kapatıldı. Sonraki girişte yeniden kuracak.`);
        break;
      }
      case "reset-password": {
        const u = await user(args[0]);
        const temp = randomToken(15);
        await setPassword(db, u.id, await hashPassword(temp));
        await db.query("DELETE FROM sessions WHERE user_id = $1", [u.id]);
        console.log(`${u.email} için geçici şifre (kullanıcıya güvenli bir kanaldan iletin, girişten sonra Hesabım'dan değiştirsin):\n  ${temp}`);
        break;
      }
      case "unlock": {
        const u = await user(args[0]);
        await db.query("UPDATE users SET failed_logins = 0, locked_until = NULL WHERE id = $1", [u.id]);
        console.log(`${u.email}: kilit açıldı.`);
        break;
      }
      default:
        console.log(HELP);
        process.exitCode = 1;
    }
  } finally {
    await db.end();
  }
}

main().catch((e) => {
  console.error("Hata:", e instanceof Error ? e.message : e);
  process.exit(1);
});
