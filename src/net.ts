/**
 * Ağ: iç ağa gidemeyen fetch (SSRF koruması) ve SMTP için Node soket açıcısı.
 *
 * Uygulama artık n8n ve PostgreSQL ile aynı sunucuda çalışıyor. Bir alan adı 127.0.0.1 ya da 10.x gibi
 * bir adrese çözülürse kontrol istekleri sunucunun iç servislerine gidebilirdi; bu yüzden bağlantı
 * kurulmadan önce çözülen her IP adresi kontrol edilir.
 */
import { lookup as dnsLookup, type LookupAddress, type LookupOptions } from "node:dns";
import { BlockList, connect as netConnect, isIP, type Socket } from "node:net";
import { Duplex } from "node:stream";
import { connect as tlsConnect } from "node:tls";
import { Agent, fetch as undiciFetch } from "undici";
import type { Opener, SmtpConn } from "./smtp";
import type { FetchFn } from "./types";

const blocked = new BlockList();
for (const [net, prefix] of [
  ["0.0.0.0", 8],
  ["10.0.0.0", 8],
  ["100.64.0.0", 10],
  ["127.0.0.0", 8],
  ["169.254.0.0", 16],
  ["172.16.0.0", 12],
  ["192.0.0.0", 24],
  ["192.168.0.0", 16],
  ["198.18.0.0", 15],
  ["224.0.0.0", 4],
  ["240.0.0.0", 4],
] as const)
  blocked.addSubnet(net, prefix, "ipv4");
for (const [net, prefix] of [
  ["::", 128],
  ["::1", 128],
  ["fc00::", 7],
  ["fe80::", 10],
  ["ff00::", 8],
  ["64:ff9b::", 96],
] as const)
  blocked.addSubnet(net, prefix, "ipv6");

export function isPrivateAddress(ip: string): boolean {
  const v = isIP(ip);
  if (v === 4) return blocked.check(ip, "ipv4");
  if (v === 6) {
    const mapped = ip.toLowerCase().match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
    if (mapped) return blocked.check(mapped[1], "ipv4");
    return blocked.check(ip, "ipv6");
  }
  return true; // tanınmayan biçim: güvenli tarafta kal
}

type LookupCb = (err: NodeJS.ErrnoException | null, address: string | LookupAddress[], family?: number) => void;

function guardedLookup(hostname: string, options: LookupOptions, cb: LookupCb): void {
  dnsLookup(hostname, { ...options, all: true }, (err, addrs) => {
    if (err) return cb(err, "");
    const list = addrs as LookupAddress[];
    const bad = list.find((a) => isPrivateAddress(a.address));
    if (bad || !list.length) {
      const e = new Error(`${hostname} iç ağ adresine çözülüyor (${bad?.address ?? "adres yok"}); güvenlik nedeniyle istek atılmadı`) as NodeJS.ErrnoException;
      e.code = "ESSRF";
      return cb(e, "");
    }
    if (options.all) return cb(null, list);
    cb(null, list[0].address, list[0].family);
  });
}

/** Kontrollerde kullanılan fetch. allowPrivate sadece yerel testte açılır. */
export function createSafeFetch(allowPrivate: boolean): FetchFn {
  const dispatcher = new Agent({
    connect: allowPrivate ? {} : { lookup: guardedLookup as never },
    connectTimeout: 10_000,
  });
  return async (url, init) => {
    if (!allowPrivate) {
      const host = new URL(url).hostname.replace(/^\[|\]$/g, "");
      if (isIP(host) && isPrivateAddress(host)) throw new Error(`${host} iç ağ adresi; güvenlik nedeniyle istek atılmadı`);
    }
    return (await undiciFetch(url, { ...(init as object), dispatcher } as never)) as unknown as Response;
  };
}

/** SMTP: node:net / node:tls soketini smtp.ts'in beklediği web akışlarına çevirir. */
export const nodeOpener: Opener = (host, port, secure) => {
  const wrap = (sock: Socket): SmtpConn => {
    sock.setTimeout(30_000, () => sock.destroy(new Error("SMTP zaman aşımı")));
    const { readable, writable } = Duplex.toWeb(sock) as unknown as { readable: ReadableStream<Uint8Array>; writable: WritableStream<Uint8Array> };
    return {
      readable,
      writable,
      startTls: () => wrap(tlsConnect({ socket: sock, servername: host })),
      close: () => void sock.end(),
    };
  };
  return wrap(secure === "tls" ? tlsConnect({ host, port, servername: host }) : netConnect({ host, port }));
};
