/**
 * Wrapper around Cloudflare's `ratelimits` binding.
 *
 * Verified against developers.cloudflare.com (Workers -> Runtime APIs -> Bindings ->
 * Rate Limiting):
 *   - the binding is declared in wrangler.jsonc with `namespace_id` plus a `simple` block
 *     holding `limit` and `period`, and `period` must be exactly 10 or 60 seconds;
 *   - Wrangler >= 4.36.0 is required;
 *   - the runtime API is `await binding.limit({ key })` returning `{ success: boolean }`;
 *   - counters are kept per Cloudflare location, so the effective global limit is
 *     approximate. That is fine for brute-force protection, which is all we use it for.
 *     If you need exact counters, use a Durable Object instead (see README).
 *
 * Because the limit and period live in wrangler.jsonc, the per-site `rateLimits` config
 * only decides WHETHER a group applies and supplies the numbers used for logging and the
 * `Retry-After` header.
 */

import type { RequestContext } from '../context';
import type { Decision, Env, RateLimit, RateLimitGroup } from '../config/types';
import { logEvent } from '../logging';

/** Groups whose missing binding we have already warned about, to avoid log spam. */
const missingBindingWarned = new Set<string>();

function bindingFor(env: Env, group: RateLimitGroup): RateLimit | undefined {
  switch (group) {
    case 'login':
      return env.RL_LOGIN;
    case 'xmlrpc':
      return env.RL_XMLRPC;
    case 'comments':
      return env.RL_COMMENTS;
    case 'general':
      return env.RL_GENERAL;
    default:
      return undefined;
  }
}

/**
 * Key shape: `<group>:<host>:<ip>`.
 *
 * The hostname is included so that one shared binding does not let traffic to site A
 * consume site B's budget. The IP is the client IP from CF-Connecting-IP only.
 */
export function rateLimitKey(group: RateLimitGroup, host: string, ip: string): string {
  return `${group}:${host}:${ip === '' ? 'unknown' : ip}`;
}

/**
 * Apply a rate limit group.
 *
 * Returns a 429 `Decision` when the limit is exceeded, or null when the request may
 * continue. A missing binding or a throwing binding fails open — a rate limiter that is
 * broken must not take the site down with it.
 */
export async function applyRateLimit(
  ctx: RequestContext,
  env: Env,
  group: RateLimitGroup,
  ruleId: string,
): Promise<Decision | null> {
  const setting = ctx.site.config.rateLimits[group];
  if (setting === null) return null;

  const binding = bindingFor(env, group);
  if (binding === undefined) {
    if (!missingBindingWarned.has(group)) {
      missingBindingWarned.add(group);
      logEvent({
        level: 'warn',
        event: 'ratelimit.bindingMissing',
        group,
        message: `No ratelimits binding for group "${group}"; rate limiting is disabled for it.`,
      });
    }
    return null;
  }

  let allowed = true;
  try {
    const result = await binding.limit({ key: rateLimitKey(group, ctx.host, ctx.ip) });
    allowed = result.success;
  } catch (error) {
    logEvent({
      level: 'warn',
      event: 'ratelimit.error',
      group,
      message: error instanceof Error ? error.message : String(error),
    });
    return null;
  }

  if (allowed) return null;

  return {
    ruleId,
    action: 'block',
    status: 429,
    retryAfterSeconds: setting.retryAfterSeconds ?? setting.period,
    detail: `${group}:${setting.limit}/${setting.period}s`,
  };
}

/** Test seam: forget which bindings we have already warned about. */
export function resetRateLimitWarnings(): void {
  missingBindingWarned.clear();
}
