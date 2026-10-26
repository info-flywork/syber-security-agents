/**
 * E-posta gönderimi: smtp.ts istemcisi + Node soketleri.
 */
import type { Config } from "./config";
import { nodeOpener } from "./net";
import { sendMail, type Opener } from "./smtp";

export type Mailer = (to: string[], subject: string, html: string) => Promise<void>;

export function smtpReady(cfg: Config): boolean {
  return !!cfg.smtp.pass;
}

export function createMailer(cfg: Config, opener: Opener = nodeOpener): Mailer {
  return async (to, subject, html) => {
    if (!cfg.smtp.pass) throw new Error("SMTP_PASS tanımlı değil");
    await sendMail(
      {
        host: cfg.smtp.host,
        port: cfg.smtp.port,
        secure: cfg.smtp.secure,
        user: cfg.smtp.user,
        pass: cfg.smtp.pass,
        from: cfg.smtp.from,
        fromName: cfg.smtp.fromName,
        to,
        subject,
        html,
        domain: cfg.smtp.from.split("@")[1] || "localhost",
      },
      opener,
    );
  };
}
