/**
 * Block responses. These are generated at the edge and never touch the origin, which is
 * the whole point: a blocked request costs the origin nothing.
 *
 * The body is deliberately minimal and says nothing about which rule fired. Rule ids are
 * only exposed when `debugHeaders` is enabled for the site.
 */

import type { RequestContext } from '../context';
import type { Decision } from '../config/types';

const BLOCK_HTML = `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Request blocked</title>
<style>body{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;margin:0;display:flex;min-height:100vh;align-items:center;justify-content:center;background:#0f1115;color:#e6e8eb}main{max-width:32rem;padding:2rem;text-align:center}h1{font-size:1.25rem;margin:0 0 .5rem}p{margin:0;color:#9aa4b2;font-size:.9rem;line-height:1.6}</style>
</head><body><main>
<h1>Request blocked</h1>
<p>This request was blocked by a security rule. If you believe this is a mistake, contact the site owner and include the time of the request.</p>
</main></body></html>`;

const RATE_LIMIT_HTML = `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Too many requests</title>
<style>body{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;margin:0;display:flex;min-height:100vh;align-items:center;justify-content:center;background:#0f1115;color:#e6e8eb}main{max-width:32rem;padding:2rem;text-align:center}h1{font-size:1.25rem;margin:0 0 .5rem}p{margin:0;color:#9aa4b2;font-size:.9rem;line-height:1.6}</style>
</head><body><main>
<h1>Too many requests</h1>
<p>You have sent too many requests in a short period. Please wait and try again.</p>
</main></body></html>`;

/**
 * Decide whether the client wants JSON. WordPress REST clients and API consumers get a
 * JSON body so their error handling does not choke on HTML.
 */
function wantsJson(ctx: RequestContext): boolean {
  if (ctx.pathLower.startsWith('/wp-json/') || ctx.pathLower === '/wp-json') return true;
  if (ctx.pathLower.startsWith('/api/')) return true;
  if (ctx.pathLower === '/xmlrpc.php') return true;
  const accept = ctx.request.headers.get('Accept') ?? '';
  if (accept.includes('application/json')) return true;
  return ctx.request.headers.get('X-Requested-With') === 'XMLHttpRequest';
}

/** Build the response for a blocking decision. */
export function buildBlockResponse(ctx: RequestContext, decision: Decision): Response {
  const status = decision.status;
  const headers = new Headers({
    // Never let a block page be cached by Cloudflare, a proxy, or the browser: the
    // decision depends on the client, not on the URL.
    'Cache-Control': 'no-store, no-cache, must-revalidate',
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer',
  });

  if (status === 429 && decision.retryAfterSeconds !== undefined) {
    headers.set('Retry-After', String(decision.retryAfterSeconds));
  }
  if (ctx.site.config.debugHeaders) {
    headers.set('X-Shield-Rule', decision.ruleId);
    if (decision.detail !== undefined) headers.set('X-Shield-Detail', decision.detail);
  }

  if (ctx.method === 'HEAD') {
    headers.set('Content-Type', 'text/html; charset=utf-8');
    return new Response(null, { status, headers });
  }

  if (wantsJson(ctx)) {
    headers.set('Content-Type', 'application/json; charset=utf-8');
    const body =
      status === 429
        ? '{"error":"too_many_requests","message":"Rate limit exceeded."}'
        : '{"error":"forbidden","message":"Request blocked by a security rule."}';
    return new Response(body, { status, headers });
  }

  headers.set('Content-Type', 'text/html; charset=utf-8');
  return new Response(status === 429 ? RATE_LIMIT_HTML : BLOCK_HTML, { status, headers });
}

/**
 * The response used when the Worker throws and the site is configured `failClosed`.
 * 503 rather than 403: the request was not judged, the shield simply broke.
 */
export function buildFailClosedResponse(): Response {
  return new Response('Service temporarily unavailable.', {
    status: 503,
    headers: {
      'Cache-Control': 'no-store',
      'Content-Type': 'text/plain; charset=utf-8',
      'Retry-After': '30',
    },
  });
}
