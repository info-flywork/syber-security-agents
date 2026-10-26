/**
 * Küçük SMTP istemcisi (AUTH LOGIN, TLS/STARTTLS). Bağlantı açma dışarıdan verilir; testte sahte sunucu.
 */

export interface SmtpConn {
  readable: ReadableStream<Uint8Array>;
  writable: WritableStream<Uint8Array>;
  startTls?: () => SmtpConn;
  close?: () => Promise<void> | void;
}

export interface SmtpOptions {
  host: string;
  port: number;
  secure: "tls" | "starttls" | "plain";
  user: string;
  pass: string;
  from: string;
  fromName: string;
  to: string[];
  subject: string;
  html: string;
  domain: string;
}

export type Opener = (host: string, port: number, secure: SmtpOptions["secure"]) => SmtpConn;

const enc = new TextEncoder();
const dec = new TextDecoder();

class Line {
  private buf = "";
  private reader: ReadableStreamDefaultReader<Uint8Array>;
  private writer: WritableStreamDefaultWriter<Uint8Array>;
  constructor(conn: SmtpConn) {
    this.reader = conn.readable.getReader();
    this.writer = conn.writable.getWriter();
  }
  release() {
    this.reader.releaseLock();
    this.writer.releaseLock();
  }
  async send(s: string) {
    await this.writer.write(enc.encode(s + "\r\n"));
  }
  async reply(): Promise<{ code: number; text: string }> {
    const lines: string[] = [];
    for (;;) {
      let idx: number;
      while ((idx = this.buf.indexOf("\r\n")) === -1) {
        const { value, done } = await this.reader.read();
        if (done) throw new Error("SMTP bağlantısı beklenmedik şekilde kapandı");
        this.buf += dec.decode(value, { stream: true });
      }
      const line = this.buf.slice(0, idx);
      this.buf = this.buf.slice(idx + 2);
      lines.push(line);
      if (line.length < 4 || line[3] !== "-") return { code: parseInt(line.slice(0, 3), 10), text: lines.join("\n") };
    }
  }
  async expect(codes: number[], step: string) {
    const r = await this.reply();
    if (!codes.includes(r.code)) throw new Error(`SMTP ${step}: ${r.text.slice(0, 200)}`);
    return r;
  }
}

export function b64(s: string): string {
  let bin = "";
  for (const b of enc.encode(s)) bin += String.fromCharCode(b);
  return btoa(bin);
}

function encodeHeader(s: string): string {
  return /^[\x20-\x7e]*$/.test(s) ? s : `=?UTF-8?B?${b64(s)}?=`;
}

export function buildMessage(o: SmtpOptions, date = new Date(), id: string = crypto.randomUUID()): string {
  const body = b64(o.html).replace(/.{1,76}/g, "$&\r\n");
  return [
    `From: ${encodeHeader(o.fromName)} <${o.from}>`,
    `To: ${o.to.join(", ")}`,
    `Subject: ${encodeHeader(o.subject)}`,
    `Date: ${date.toUTCString().replace("GMT", "+0000")}`,
    `Message-ID: <${id}@${o.domain}>`,
    "MIME-Version: 1.0",
    "Content-Type: text/html; charset=UTF-8",
    "Content-Transfer-Encoding: base64",
    "",
    body,
  ].join("\r\n");
}

export async function sendMail(o: SmtpOptions, open: Opener): Promise<void> {
  if (o.secure === "plain") throw new Error("Şifresiz SMTP kapalı: SMTP_SECURE=tls ya da starttls olmalı");
  let conn = open(o.host, o.port, o.secure);
  let io = new Line(conn);
  try {
    await io.expect([220], "karşılama");
    await io.send(`EHLO ${o.domain}`);
    await io.expect([250], "EHLO");
    if (o.secure === "starttls") {
      await io.send("STARTTLS");
      await io.expect([220], "STARTTLS");
      if (!conn.startTls) throw new Error("STARTTLS desteklenmiyor");
      io.release();
      conn = conn.startTls();
      io = new Line(conn);
      await io.send(`EHLO ${o.domain}`);
      await io.expect([250], "EHLO (TLS)");
    }
    await io.send("AUTH LOGIN");
    await io.expect([334], "AUTH");
    await io.send(b64(o.user));
    await io.expect([334], "AUTH kullanıcı");
    await io.send(b64(o.pass));
    await io.expect([235], "AUTH şifre");
    await io.send(`MAIL FROM:<${o.from}>`);
    await io.expect([250], "MAIL FROM");
    for (const rcpt of o.to) {
      await io.send(`RCPT TO:<${rcpt}>`);
      await io.expect([250, 251], `RCPT ${rcpt}`);
    }
    await io.send("DATA");
    await io.expect([354], "DATA");
    await io.send(buildMessage(o).replace(/\r\n\./g, "\r\n..") + "\r\n.");
    await io.expect([250], "gönderim");
    await io.send("QUIT");
    await io.reply().catch(() => undefined);
  } finally {
    try {
      io.release();
    } catch {
      /* zaten bırakıldı */
    }
    await conn.close?.();
  }
}
