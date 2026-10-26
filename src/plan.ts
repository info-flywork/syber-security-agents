import { COMMON_SENSITIVE_PATHS, MAX_SENSITIVE } from "./defaults";
import type { FetchFn, SiteConfig } from "./types";

/** Bütçe aşılınca istek atmayan fetch sarmalayıcısı. */
export function budgeted(fetchFn: FetchFn, limit: number): FetchFn & { used: () => number } {
  let n = 0;
  const f = (async (u: string, i?: RequestInit) => {
    if (++n > limit) throw new Error("istek bütçesi doldu");
    return fetchFn(u, i);
  }) as FetchFn & { used: () => number };
  f.used = () => n;
  return f;
}

export function sensitiveList(site: SiteConfig): string[] {
  // Siteye özel yollar önce; toplam sınır içinde kalır
  return [...new Set([...site.extraPaths, ...COMMON_SENSITIVE_PATHS])].slice(0, MAX_SENSITIVE - site.pages.length);
}
