/**
 * Optional Turnstile challenge action.
 *
 * Off by default (`challenge.enabled: false`). When a rule returns `challenge` instead of
 * `block`, the visitor gets an interstitial page with a Cloudflare Turnstile widget. The
 * widget posts its token back to `/__shield/challenge`; if Turnstile's siteverify accepts
 * it, the shield sets a signed clearance cookie and redirects the visitor onwards.
 *
 * The cookie is an HMAC-SHA256 over `<expiry>.<client ip>`, keyed by the
 * SHIELD_COOKIE_SECRET secret. Binding the signature to the IP means a stolen cookie is
 * useless from another address, and the expiry caps how long one solve lasts.
 *
 * Requirements (all secrets, never written to a file):
 *   npx wrangler secret put SHIELD_COOKIE_SECRET
 *   npx wrangler secret put TURNSTILE_SECRET_KEY
 * plus TURNSTILE_SITE_KEY, which is public and may live in `vars`.
 *
 * COST NOTE: verifying a token calls Turnstile's API, which is a subrequest. That is one
 * network round trip, so the challenge action is only ever taken on the interstitial
 * itself, never on ordinary traffic.
 */

import type { RequestContext } from '../context';
import type { ChallengeConfig, Env } from '../config/types';
import { logEvent } from '../logging';

const TURNSTILE_VERIFY_URL = 'https://challenges.cloudflare.com/turnstile/v0/siteverify';
const CHALLENGE_PATH = '/__shield/challenge';

/** Base64url without padding, so the value is cookie-safe. */
function toBase64Url(bytes: ArrayBuffer): string {
  let binary = '';
  const view = new Uint8Array(bytes);
  for (let i = 0; i < view.length; i++) binary += String.fromCharCode(view[i] as number);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function sign(secret: string, payload: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  const signature = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(payload));
  return toBase64Url(signature);
}

function constantTimeEqual(a: string, b: string): boolean {
  const encoder = new TextEncoder();
  const left = encoder.encode(a);
  const right = encoder.encode(b);
  const length = Math.max(left.length, right.length);
  let diff = left.length ^ right.length;
  for (let i = 0; i < length; i++) diff |= (left[i] ?? 0) ^ (right[i] ?? 0);
  return diff === 0;
}

/** Build the cookie value: `<expiryEpochSeconds>.<signature>`. */
export async function issueClearance(
  secret: string,
  ip: string,
  ttlSeconds: number,
  now: number,
): Promise<string> {
  const expiry = Math.floor(now / 1000) + ttlSeconds;
  const signature = await sign(secret, `${expiry}.${ip}`);
  return `${expiry}.${signature}`;
}

/** Verify a clearance cookie value. Returns false for anything malformed or expired. */
export async function verifyClearance(
  secret: string,
  ip: string,
  value: string,
  now: number,
): Promise<boolean> {
  const separator = value.indexOf('.');
  if (separator <= 0) return false;
  const expiryText = value.slice(0, separator);
  const signature = value.slice(separator + 1);
  if (!/^\d{1,12}$/.test(expiryText) || signature.length === 0) return false;

  const expiry = Number(expiryText);
  if (expiry * 1000 <= now) return false;

  const expected = await sign(secret, `${expiry}.${ip}`);
  return constantTimeEqual(signature, expected);
}

function readCookie(header: string | null, name: string): string | null {
  if (header === null) return null;
  for (const part of header.split(';')) {
    const trimmed = part.trim();
    if (trimmed.startsWith(`${name}=`)) return decodeURIComponent(trimmed.slice(name.length + 1));
  }
  return null;
}

/** True when the visitor already holds a valid clearance cookie for this IP. */
export async function hasClearance(ctx: RequestContext, env: Env, now: number): Promise<boolean> {
  const config = ctx.site.config.challenge;
  const secret = env.SHIELD_COOKIE_SECRET;
  if (!config.enabled || secret === undefined || secret === '') return false;

  const value = readCookie(ctx.request.headers.get('Cookie'), config.cookieName);
  if (value === null) return false;
  return verifyClearance(secret, ctx.ip, value, now);
}

function challengeHtml(siteKey: string, redirectTo: string): string {
  // The redirect target is embedded as a JSON string inside a script tag. It is
  // percent-encoded first so it can never contain `<`, `"` or a quote that would break
  // out of the attribute or the script block.
  const safeRedirect = JSON.stringify(encodeURI(redirectTo));
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Checking your browser</title>
<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
<style>body{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;margin:0;display:flex;min-height:100vh;align-items:center;justify-content:center;background:#0f1115;color:#e6e8eb}main{max-width:28rem;padding:2rem;text-align:center}h1{font-size:1.15rem;margin:0 0 .5rem}p{margin:0 0 1.5rem;color:#9aa4b2;font-size:.9rem;line-height:1.6}</style>
</head><body><main>
<h1>Checking your browser</h1>
<p>This takes a moment and happens once. Please make sure JavaScript is enabled.</p>
<form id="shield-form" method="POST" action="${CHALLENGE_PATH}">
  <input type="hidden" name="redirect" id="shield-redirect">
  <div class="cf-turnstile" data-sitekey="${siteKey}" data-callback="shieldSolved"></div>
</form>
<script>
  var redirect = ${safeRedirect};
  document.getElementById("shield-redirect").value = redirect;
  function shieldSolved() { document.getElementById("shield-form").submit(); }
</script>
</main></body></html>`;
}

/** The interstitial page. Returns 403 with the widget, never touching the origin. */
export function buildChallengeResponse(ctx: RequestContext, env: Env): Response {
  const siteKey = env.TURNSTILE_SITE_KEY;
  if (siteKey === undefined || siteKey === '') {
    // Misconfigured challenge: degrade to a plain block rather than an empty page.
    return new Response('Request blocked.', {
      status: 403,
      headers: { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store' },
    });
  }
  return new Response(challengeHtml(siteKey, ctx.url.pathname + ctx.url.search), {
    status: 403,
    headers: {
      'Content-Type': 'text/html; charset=utf-8',
      'Cache-Control': 'no-store, no-cache, must-revalidate',
      'X-Content-Type-Options': 'nosniff',
      'Referrer-Policy': 'no-referrer',
    },
  });
}

interface SiteVerifyResponse {
  success?: unknown;
}

/**
 * Handle `POST /__shield/challenge`: verify the Turnstile token, then set the clearance
 * cookie and redirect back to where the visitor was going.
 */
export async function handleChallengeSubmission(
  request: Request,
  env: Env,
  config: ChallengeConfig,
  now: number,
): Promise<Response> {
  const secret = env.TURNSTILE_SECRET_KEY;
  const cookieSecret = env.SHIELD_COOKIE_SECRET;
  if (secret === undefined || cookieSecret === undefined) {
    return new Response('Challenge is not configured.', { status: 503 });
  }
  if (request.method !== 'POST') {
    return new Response('Method not allowed.', { status: 405 });
  }

  const form = await request.formData();
  const token = form.get('cf-turnstile-response');
  const ip = request.headers.get('CF-Connecting-IP') ?? '';
  if (typeof token !== 'string' || token === '') {
    return new Response('Missing challenge token.', { status: 400 });
  }

  const body = new FormData();
  body.append('secret', secret);
  body.append('response', token);
  if (ip !== '') body.append('remoteip', ip);

  let verified = false;
  try {
    const response = await fetch(TURNSTILE_VERIFY_URL, { method: 'POST', body });
    const result = (await response.json()) as SiteVerifyResponse;
    verified = result.success === true;
  } catch (error) {
    logEvent({
      level: 'error',
      event: 'challenge.verifyFailed',
      message: error instanceof Error ? error.message : String(error),
    });
    return new Response('Could not verify the challenge. Please try again.', { status: 503 });
  }

  if (!verified) {
    return new Response('Challenge failed.', { status: 403 });
  }

  // Only same-origin, absolute-path redirects are accepted, so the interstitial cannot be
  // turned into an open redirect.
  const requested = form.get('redirect');
  const target =
    typeof requested === 'string' && requested.startsWith('/') && !requested.startsWith('//')
      ? requested
      : '/';

  const clearance = await issueClearance(cookieSecret, ip, config.ttlSeconds, now);
  return new Response(null, {
    status: 302,
    headers: {
      Location: target,
      'Cache-Control': 'no-store',
      'Set-Cookie': `${config.cookieName}=${clearance}; Path=/; Max-Age=${config.ttlSeconds}; HttpOnly; Secure; SameSite=Lax`,
    },
  });
}

export const CHALLENGE_SUBMIT_PATH = CHALLENGE_PATH;
