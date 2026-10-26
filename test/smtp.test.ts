import { describe, expect, it } from "vitest";
import { b64, buildMessage, sendMail, type SmtpConn, type SmtpOptions } from "../src/smtp";

/** Sahte SMTP sunucusu: istemcinin yazdıklarını kaydeder, script'e göre cevap verir. */
function fakeServer(script: (cmd: string) => string, tls = false) {
  const log: string[] = [];
  let upgraded = false;
  const make = (): SmtpConn => {
    let ctrl!: ReadableStreamDefaultController<Uint8Array>;
    const readable = new ReadableStream<Uint8Array>({ start: (c) => void (ctrl = c) });
    const say = (s: string) => ctrl.enqueue(new TextEncoder().encode(s));
    let pending = "";
    let inData = false;
    const writable = new WritableStream<Uint8Array>({
      write(chunk) {
        pending += new TextDecoder().decode(chunk);
        let i: number;
        while ((i = pending.indexOf("\r\n")) !== -1) {
          const line = pending.slice(0, i);
          pending = pending.slice(i + 2);
          if (inData) {
            log.push("DATA> " + line);
            if (line === ".") {
              inData = false;
              say("250 Ok: queued\r\n");
            }
            continue;
          }
          log.push((upgraded ? "TLS " : "") + line);
          if (line === "DATA") inData = true;
          say(script(line));
        }
      },
    });
    setTimeout(() => !upgraded && say("220 mail ESMTP\r\n"), 0);
    return { readable, writable, startTls: tls ? () => ((upgraded = true), make()) : undefined };
  };
  return { log, open: () => make() };
}

const o: SmtpOptions = {
  host: "mail.example", port: 465, secure: "tls", user: "u@ornek.com", pass: "sifre", from: "u@ornek.com", fromName: "Site Gözcü",
  to: ["a@ornek.com", "b@ornek.com"], subject: "🔴 Örnek: test", html: "<p>Merhaba\n.nokta</p>", domain: "ornek.com",
};
const ok = (c: string) =>
  c.startsWith("EHLO") ? "250-mail\r\n250-AUTH LOGIN\r\n250 8BITMIME\r\n"
  : c === "STARTTLS" ? "220 Ready\r\n"
  : c === "AUTH LOGIN" ? "334 VXNlcm5hbWU6\r\n"
  : c === b64("u@ornek.com") ? "334 UGFzc3dvcmQ6\r\n"
  : c === b64("sifre") ? "235 OK\r\n"
  : c.startsWith("MAIL") || c.startsWith("RCPT") ? "250 Ok\r\n"
  : c === "DATA" ? "354 go\r\n"
  : c === "QUIT" ? "221 Bye\r\n"
  : "500 ?\r\n";

describe("SMTP", () => {
  it("TLS ile tam diyalog, çok satırlı EHLO", async () => {
    const s = fakeServer(ok);
    await sendMail(o, s.open);
    expect(s.log.filter((l) => !l.startsWith("DATA> "))).toEqual([
      "EHLO ornek.com", "AUTH LOGIN", b64("u@ornek.com"), b64("sifre"), "MAIL FROM:<u@ornek.com>", "RCPT TO:<a@ornek.com>", "RCPT TO:<b@ornek.com>", "DATA", "QUIT",
    ]);
  });
  it("STARTTLS'te şifre yalnızca TLS üzerinden gider", async () => {
    const s = fakeServer(ok, true);
    await sendMail({ ...o, secure: "starttls", port: 587 }, s.open);
    expect(s.log.find((l) => l.endsWith(b64("sifre")))?.startsWith("TLS ")).toBe(true);
  });
  it("şifresiz bağlantıyı reddeder; yanlış şifrede anlaşılır hata", async () => {
    await expect(sendMail({ ...o, secure: "plain" }, fakeServer(ok).open)).rejects.toThrow(/Şifresiz/);
    await expect(sendMail(o, fakeServer((c) => (c === b64("sifre") ? "535 Authentication failed\r\n" : ok(c))).open)).rejects.toThrow(/AUTH şifre: 535/);
  });
  it("mesaj UTF-8 başlıklı, base64 gövdeli", () => {
    const m = buildMessage(o, new Date("2026-10-16T10:00:00Z"), "id1");
    expect(m).toContain("Subject: =?UTF-8?B?");
    expect(m).toContain("Message-ID: <id1@ornek.com>");
    const body = m.split("\r\n\r\n")[1].replace(/\r\n/g, "");
    expect(new TextDecoder().decode(Uint8Array.from(atob(body), (c) => c.charCodeAt(0)))).toBe(o.html);
  });
});
