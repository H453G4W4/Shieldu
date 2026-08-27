/**
 * The decision pipeline. Ordered, first match wins, allow list first.
 *
 * Order (kept in sync with README.md and docs/config-reference.md):
 *   1. `/__shield/*` endpoints            -- handled in index.ts, before this runs
 *   2. IP/CIDR/ASN/country allow list     -> ALLOW, skipping every block rule
 *   3. IP/CIDR block list                 -> BLOCK
 *   4. ASN block list                     -> BLOCK
 *   5. Country block list / allow mode    -> BLOCK
 *   6. Method rules                       -> BLOCK
 *   7. Generic sensitive paths + anomalies-> BLOCK
 *   8. WordPress rules (or WP probes)     -> BLOCK or RATE_LIMIT
 *   9. User-agent rules                   -> BLOCK
 *  10. `general` rate limit               -> 429
 *  11. Forward to origin, then headers    -- in index.ts
 *
 * Steps 3-5 all come out of one compiled block list, so the IP/ASN/country checks are a
 * single pass; the returned rule id still says which of the three matched.
 */

import { hasClearance } from '../actions/challenge';
import type { RequestContext } from '../context';
import type { Decision, Env } from '../config/types';
import { blockDecisionForMatch, isAllowListed, matchList } from './lists';
import { evaluateMethods } from './methods';
import { evaluateAnomalies, evaluateScannerPaths } from './paths';
import { applyRateLimit } from './ratelimit';
import { evaluateUserAgent } from './useragent';
import { evaluateWordPress, evaluateWordPressProbes } from './wordpress';

/** The decision returned when nothing matched. */
export const ALLOW_DECISION: Decision = { ruleId: 'default.allow', action: 'allow', status: 200 };

/**
 * Optional Turnstile step (off by default).
 *
 * When `challenge.enabled` is on and the matched rule id is listed in
 * `challenge.challengeRules`, a would-be block becomes an interstitial instead: a visitor
 * who solves it gets a signed clearance cookie and is let through for `ttlSeconds`. Rules
 * not listed still block outright.
 */
async function maybeChallenge(
  ctx: RequestContext,
  env: Env,
  decision: Decision,
): Promise<Decision> {
  const config = ctx.site.config.challenge;
  if (!config.enabled || decision.action !== 'block') return decision;

  let matches = false;
  for (let i = 0; i < config.challengeRules.length; i++) {
    if (decision.ruleId.startsWith(config.challengeRules[i] as string)) {
      matches = true;
      break;
    }
  }
  if (!matches) return decision;

  if (await hasClearance(ctx, env, Date.now())) {
    return { ruleId: 'challenge.cleared', action: 'allow', status: 200, detail: decision.ruleId };
  }
  return { ...decision, action: 'challenge' };
}

/** Country allow mode: only the listed countries may enter. */
function evaluateCountryAllowMode(ctx: RequestContext): Decision | null {
  const site = ctx.site;
  if (site.config.countryMode !== 'allow') return null;
  if (site.countryAllow.size === 0) return null;
  // An unknown country cannot satisfy an allow list. This is the one place where missing
  // `request.cf` data changes the outcome, so it is called out in the docs.
  if (ctx.country !== '' && site.countryAllow.has(ctx.country)) return null;
  return {
    ruleId: 'list.allowMode.country',
    action: 'block',
    status: 403,
    detail: ctx.country === '' ? 'unknown' : ctx.country,
  };
}

/**
 * Evaluate every rule group in order.
 *
 * `rateLimit` decisions produced by the WordPress group are resolved here against the
 * binding, so the caller only ever sees `allow` or `block`.
 */
export async function evaluate(ctx: RequestContext, env: Env): Promise<Decision> {
  const decision = await evaluateRules(ctx, env);
  return maybeChallenge(ctx, env, decision);
}

async function evaluateRules(ctx: RequestContext, env: Env): Promise<Decision> {
  const site = ctx.site;

  // -- 2. Allow list wins over everything below. --
  const allowMatch = isAllowListed(site.allow, ctx.ipBytes, ctx.asn, ctx.country);
  if (allowMatch !== null) {
    return {
      ruleId: `list.allow.${allowMatch.kind}`,
      action: 'allow',
      status: 200,
      detail: allowMatch.detail,
    };
  }

  // Explicitly allowed paths bypass the path/WordPress/UA groups but not the lists above.
  const pathExempt = site.extraAllowedPaths.has(ctx.pathDecoded);

  // -- 3, 4, 5. Block list (ip, asn, and country when countryMode is "block"). --
  const blockMatch = matchList(site.block, ctx.ipBytes, ctx.asn, ctx.country, {
    includeCountry: site.config.countryMode === 'block',
  });
  if (blockMatch !== null) return blockDecisionForMatch(blockMatch);

  // -- 5b. Country allow mode. --
  const countryDecision = evaluateCountryAllowMode(ctx);
  if (countryDecision !== null) return countryDecision;

  // -- 6. Methods. --
  const methodDecision = evaluateMethods(ctx);
  if (methodDecision !== null) return methodDecision;

  if (!pathExempt) {
    // -- 7. Generic paths and anomalies. --
    const anomalyDecision = evaluateAnomalies(ctx);
    if (anomalyDecision !== null) return anomalyDecision;

    const pathDecision = evaluateScannerPaths(ctx);
    if (pathDecision !== null) return pathDecision;

    // -- 8. WordPress. --
    const wpDecision =
      site.config.type === 'wordpress' ? evaluateWordPress(ctx) : evaluateWordPressProbes(ctx);
    if (wpDecision !== null) {
      if (wpDecision.action === 'rateLimit') {
        const group = wpDecision.detail;
        if (group === 'login' || group === 'xmlrpc' || group === 'comments') {
          const limited = await applyRateLimit(ctx, env, group, wpDecision.ruleId);
          if (limited !== null) return limited;
        }
      } else {
        return wpDecision;
      }
    }

    // -- 9. User agent. --
    const uaDecision = evaluateUserAgent(ctx);
    if (uaDecision !== null) return uaDecision;
  }

  // -- 10. Optional per-IP burst limit for the whole site. --
  const generalLimited = await applyRateLimit(ctx, env, 'general', 'rateLimit.general');
  if (generalLimited !== null) return generalLimited;

  return ALLOW_DECISION;
}
