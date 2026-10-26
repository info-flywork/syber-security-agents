import { describe, expect, it } from "vitest";
import { can } from "../src/accounts";
import { isPrivateAddress } from "../src/net";
import {
  base32Decode,
  base32Encode,
  decryptSecret,
  encryptSecret,
  hashPassword,
  newRecoveryCodes,
  normalizeRecovery,
  passwordProblem,
  totpAt,
  verifyPassword,
  verifyTotp,
} from "../src/security";

// RFC 6238 Ek B — SHA-1 anahtarı "12345678901234567890"
const RFC_SECRET = base32Encode(Buffer.from("12345678901234567890"));

describe("TOTP", () => {
  it("RFC 6238 test vektörlerini üretir", () => {
    expect(RFC_SECRET).toBe("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
    const cases: [number, string][] = [
      [59, "94287082"],
      [1111111109, "07081804"],
      [1111111111, "14050471"],
      [1234567890, "89005924"],
      [2000000000, "69279037"],
    ];
    for (const [t, code] of cases) expect(totpAt(RFC_SECRET, Math.floor(t / 30), 8)).toBe(code);
  });
  it("±1 adım kaymayı kabul eder, aynı ya da eski adımı tekrar kabul etmez", () => {
    const now = 1_800_000_000_000;
    const step = Math.floor(now / 30_000);
    expect(verifyTotp(RFC_SECRET, totpAt(RFC_SECRET, step), 0, now)).toBe(step);
    expect(verifyTotp(RFC_SECRET, totpAt(RFC_SECRET, step - 1), 0, now)).toBe(step - 1);
    expect(verifyTotp(RFC_SECRET, totpAt(RFC_SECRET, step - 2), 0, now)).toBe(null);
    expect(verifyTotp(RFC_SECRET, totpAt(RFC_SECRET, step), step, now)).toBe(null);
    expect(verifyTotp(RFC_SECRET, "12345", 0, now)).toBe(null);
    expect(verifyTotp(RFC_SECRET, "abcdef", 0, now)).toBe(null);
  });
  it("base32 gidiş-dönüş", () => {
    const b = Buffer.from([0, 1, 2, 250, 251, 252, 253, 254, 255]);
    expect(base32Decode(base32Encode(b)).equals(b)).toBe(true);
  });
});

describe("şifre", () => {
  it("özet doğrular, yanlış şifreyi reddeder, her özet farklı tuzlu", async () => {
    const h = await hashPassword("çok-güçlü-bir-şifre-42");
    expect(h.startsWith("scrypt$32768$8$3$")).toBe(true);
    expect(await verifyPassword("çok-güçlü-bir-şifre-42", h)).toBe(true);
    expect(await verifyPassword("çok-güçlü-bir-şifre-43", h)).toBe(false);
    expect(await hashPassword("çok-güçlü-bir-şifre-42")).not.toBe(h);
    expect(await verifyPassword("x", "bozuk")).toBe(false);
  });
  it("zayıf şifreleri reddeder", () => {
    expect(passwordProblem("kisa", "a@b.com")).toMatch(/en az/);
    expect(passwordProblem("aaaaaaaaaaaaaaaa", "a@b.com")).toMatch(/tekrarlı/);
    expect(passwordProblem("mehmet-2026-sifrem!", "mehmet@ornek.com")).toMatch(/e-posta/);
    expect(passwordProblem("Mavi-Kedi-Kosar-77", "ali@ornek.com")).toBe(null);
  });
});

describe("2FA sırrı ve kurtarma kodları", () => {
  it("şifreli saklanır, yanlış anahtarla açılmaz", () => {
    const k = "x".repeat(40);
    const enc = encryptSecret("GEZDGNBV", k);
    expect(enc).not.toContain("GEZDGNBV");
    expect(decryptSecret(enc, k)).toBe("GEZDGNBV");
    expect(() => decryptSecret(enc, "y".repeat(40))).toThrow();
  });
  it("8 benzersiz kod; girişte tire ve büyük harf fark etmez", () => {
    const codes = newRecoveryCodes();
    expect(new Set(codes).size).toBe(8);
    expect(codes[0]).toMatch(/^[a-z2-7]{5}-[a-z2-7]{5}$/);
    expect(normalizeRecovery(codes[0].toUpperCase().replace("-", " "))).toBe(normalizeRecovery(codes[0]));
  });
});

describe("iç ağ koruması (SSRF)", () => {
  it("özel, döngü ve bağlantı-yerel adresleri engeller", () => {
    for (const ip of ["127.0.0.1", "10.1.2.3", "172.17.0.1", "192.168.1.1", "169.254.169.254", "100.64.0.1", "0.0.0.0", "::1", "fd00::1", "fe80::1", "::ffff:127.0.0.1", "::ffff:10.0.0.1"]) {
      expect(isPrivateAddress(ip), ip).toBe(true);
    }
    for (const ip of ["93.184.216.34", "1.1.1.1", "2606:4700:4700::1111", "172.32.0.1"]) expect(isPrivateAddress(ip), ip).toBe(false);
  });
});

describe("roller", () => {
  it("görüntüleyen yönetemez; yönetici sahiplere dokunamaz", () => {
    expect(can.manageSites("viewer")).toBe(false);
    expect(can.manageSites("admin")).toBe(true);
    expect(can.viewAudit("viewer")).toBe(false);
    expect(can.inviteAs("admin", "owner")).toBe(false);
    expect(can.inviteAs("admin", "admin")).toBe(true);
    expect(can.changeMember("admin", "owner")).toBe(false);
    expect(can.changeMember("admin", "viewer", "owner")).toBe(false);
    expect(can.changeMember("admin", "viewer", "admin")).toBe(true);
    expect(can.changeMember("owner", "owner", "viewer")).toBe(true);
  });
});
