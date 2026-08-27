/**
 * Response security headers.
 *
 * Applied to origin responses only, never to block pages (those set their own minimal
 * header set). The response body is streamed straight through: we construct a new
 * `Response` around the original `body` stream so nothing is ever buffered in the Worker.
 *
 * Invariants:
 *   - the status code is never changed;
 *   - `Set-Cookie` is never touched;
 *   - a header the origin already set is only overwritten when the site explicitly asks
 *     for it (HSTS, CSP), so an origin that already has a stricter policy keeps it.
 */

import type { HeadersConfig } from '../config/types';

/** Statuses whose responses must not carry a body. Reconstructing them needs care. */
const NULL_BODY_STATUSES = new Set([101, 204, 205, 304]);

function frameOptionsFor(frameAncestors: string): string | null {
  const value = frameAncestors.trim().toLowerCase();
  if (value === "'none'") return 'DENY';
  if (value === "'self'") return 'SAMEORIGIN';
  // X-Frame-Options has no multi-origin form; modern browsers use frame-ancestors anyway.
  return null;
}

function buildCsp(config: HeadersConfig): string | null {
  const frameAncestors = config.frameAncestors.trim();
  if (config.csp === null) {
    return frameAncestors === '' ? null : `frame-ancestors ${frameAncestors}`;
  }
  const policy = config.csp.trim();
  if (frameAncestors === '' || policy.toLowerCase().includes('frame-ancestors')) return policy;
  const separator = policy.endsWith(';') ? ' ' : '; ';
  return `${policy}${separator}frame-ancestors ${frameAncestors}`;
}

function buildHsts(config: HeadersConfig): string | null {
  if (!config.hsts) return null;
  let value = `max-age=${config.hstsMaxAge}`;
  if (config.hstsIncludeSubdomains) value += '; includeSubDomains';
  // `preload` is meaningless (and harmful) without includeSubDomains.
  if (config.hstsPreload && config.hstsIncludeSubdomains) value += '; preload';
  return value;
}

/**
 * Wrap an origin response with the configured security headers.
 *
 * Returns the original response untouched for WebSocket upgrades and null-body statuses,
 * where reconstructing the response is either impossible or pointless.
 */
export function applySecurityHeaders(response: Response, config: HeadersConfig): Response {
  // A WebSocket upgrade carries a live socket on the response object; cloning it would
  // drop the socket, so leave it alone.
  const maybeWebSocket = (response as Response & { webSocket?: unknown }).webSocket;
  if (maybeWebSocket !== undefined && maybeWebSocket !== null) return response;
  if (NULL_BODY_STATUSES.has(response.status)) return response;

  // `new Response(body, init)` keeps the status, statusText and headers of `init` and
  // passes the body through as a stream. Nothing is read into memory here.
  const out = new Response(response.body, response);
  const headers = out.headers;

  if (config.removeXPoweredBy) {
    headers.delete('X-Powered-By');
    headers.delete('X-AspNet-Version');
    headers.delete('X-AspNetMvc-Version');
  }

  if (config.nosniff) headers.set('X-Content-Type-Options', 'nosniff');

  if (config.referrerPolicy !== '') headers.set('Referrer-Policy', config.referrerPolicy);
  if (config.permissionsPolicy !== '') {
    headers.set('Permissions-Policy', config.permissionsPolicy);
  }
  if (config.coop !== null && config.coop !== '') {
    headers.set('Cross-Origin-Opener-Policy', config.coop);
  }

  const frameOptions = frameOptionsFor(config.frameAncestors);
  if (frameOptions !== null) headers.set('X-Frame-Options', frameOptions);

  const csp = buildCsp(config);
  if (csp !== null) {
    const headerName = config.cspReportOnly
      ? 'Content-Security-Policy-Report-Only'
      : 'Content-Security-Policy';
    // Do not stack a second policy on top of one the origin already sends: two CSP
    // headers are intersected by the browser, which silently breaks pages.
    if (headers.get(headerName) === null) headers.set(headerName, csp);
  }

  const hsts = buildHsts(config);
  // Only meaningful over HTTPS, and Cloudflare terminates TLS, so the visitor connection
  // is what matters here, not the origin leg.
  if (hsts !== null) headers.set('Strict-Transport-Security', hsts);

  return out;
}
