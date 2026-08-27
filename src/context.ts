/**
 * Per-request context. Built once, at the top of the handler, so every rule module reads
 * pre-computed values instead of re-parsing the URL or re-lowercasing the path.
 */

import type { ResolvedSite } from './config/loader';
import type { IpBytes } from './engine/ip';
import { parseIp } from './engine/ip';

export interface RequestContext {
  request: Request;
  url: URL;
  /** Lowercase hostname, no port. */
  host: string;
  /** Raw pathname from the URL. */
  path: string;
  /** Lowercase pathname. Every path rule matches against this. */
  pathLower: string;
  /** Percent-decoded lowercase pathname, or `pathLower` when decoding fails. */
  pathDecoded: string;
  /** Uppercase HTTP method. */
  method: string;
  /** Client IP from CF-Connecting-IP, or an empty string when absent (local dev). */
  ip: string;
  /** Parsed client IP, or null when absent/malformed. */
  ipBytes: IpBytes | null;
  /** ISO country from request.cf, or an empty string when unknown. */
  country: string;
  /** ASN from request.cf, or 0 when unknown. */
  asn: number;
  /** AS organisation name from request.cf, or an empty string. */
  asOrg: string;
  /** True when Cloudflare marks the country as being in the EU. */
  isEuCountry: boolean;
  /** Raw User-Agent header, or an empty string. */
  ua: string;
  /** Lowercase User-Agent. */
  uaLower: string;
  site: ResolvedSite;
}

/**
 * `request.cf` is absent in `wrangler dev --local` and in the test runner, so every field
 * is read defensively. Unknown geo data must never crash the shield; it simply means the
 * geo rules cannot match.
 */
function readCf(request: Request): {
  country: string;
  asn: number;
  asOrg: string;
  isEuCountry: boolean;
} {
  const cf = request.cf as
    | { country?: unknown; asn?: unknown; asOrganization?: unknown; isEUCountry?: unknown }
    | undefined;
  if (cf === undefined || cf === null) {
    return { country: '', asn: 0, asOrg: '', isEuCountry: false };
  }
  const rawCountry = typeof cf.country === 'string' ? cf.country.toUpperCase() : '';
  // Cloudflare uses "T1" for Tor exit nodes and "XX" when the country is unknown.
  const country = rawCountry === 'XX' ? '' : rawCountry;
  const asn = typeof cf.asn === 'number' && Number.isFinite(cf.asn) ? cf.asn : 0;
  const asOrg = typeof cf.asOrganization === 'string' ? cf.asOrganization : '';
  // isEUCountry arrives as the string "1" on the edge, but tests may set a boolean.
  const isEuCountry = cf.isEUCountry === '1' || cf.isEUCountry === true;
  return { country, asn, asOrg, isEuCountry };
}

function decodePath(pathLower: string): string {
  try {
    return decodeURIComponent(pathLower).toLowerCase();
  } catch {
    // A malformed percent-escape is itself suspicious; the anomaly check catches it.
    return pathLower;
  }
}

export function buildContext(request: Request, url: URL, site: ResolvedSite): RequestContext {
  // Only CF-Connecting-IP is trusted. X-Forwarded-For is attacker-controlled and is
  // deliberately never read anywhere in this Worker.
  const ip = request.headers.get('CF-Connecting-IP') ?? '';
  const ua = request.headers.get('User-Agent') ?? '';
  const cf = readCf(request);
  const path = url.pathname;
  const pathLower = path.toLowerCase();

  return {
    request,
    url,
    host: url.hostname.toLowerCase(),
    path,
    pathLower,
    pathDecoded: decodePath(pathLower),
    method: request.method.toUpperCase(),
    ip,
    ipBytes: ip === '' ? null : parseIp(ip),
    country: cf.country,
    asn: cf.asn,
    asOrg: cf.asOrg,
    isEuCountry: cf.isEuCountry,
    ua,
    uaLower: ua.toLowerCase(),
    site,
  };
}
