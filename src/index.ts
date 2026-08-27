/**
 * edge-shield -- entry point.
 *
 * Responsibilities, in order:
 *   1. answer `/__shield/*` (health + admin API) without ever touching the origin;
 *   2. resolve the site config for the hostname (unknown host -> pass through);
 *   3. run the rule pipeline;
 *   4. block, or forward to the origin and add security headers to the response.
 *
 * The whole handler is wrapped in try/catch. On an unexpected error the request is
 * forwarded to the origin unchanged (fail open), unless the site sets `failClosed: true`.
 * A security layer that takes the site down when it has a bug is worse than no layer.
 */

import { handleShieldRequest, isShieldPath } from './admin/api';
import { buildFailClosedResponse, buildBlockResponse } from './actions/block';
import { loadSite, shouldLogUnknownHost } from './config/loader';
import type { ResolvedSite } from './config/loader';
import { defaultGlobalConfig } from './config/defaults';
import type { Decision, Env } from './config/types';
import { buildContext } from './context';
import type { RequestContext } from './context';
import { applySecurityHeaders } from './engine/headers';
import { evaluate } from './engine/pipeline';
import { logDecision, logEvent } from './logging';

/**
 * Forward to the origin. Passing the original `Request` keeps method, headers and body
 * intact; Cloudflare resolves it to the zone's origin because the Worker sits on a route.
 */
async function forwardToOrigin(ctx: RequestContext): Promise<Response> {
  const response = await fetch(ctx.request);
  return applySecurityHeaders(response, ctx.site.config.headers);
}

/**
 * Turn a decision into a response.
 *
 * `monitor` semantics: a site in `mode: "monitor"`, or a rule whose action is `monitor`,
 * logs exactly what it would have done and then lets the request through. This is how a
 * new site is rolled out safely.
 */
async function respond(
  ctx: RequestContext,
  decision: Decision,
  startedAt: number,
): Promise<Response> {
  const isBlocking = decision.action === 'block' || decision.action === 'challenge';
  const monitored = isBlocking && ctx.site.config.mode === 'monitor';

  if (decision.action !== 'allow' || ctx.site.config.logAllowed) {
    logDecision(ctx, decision, { monitored, durationMs: Date.now() - startedAt });
  }

  if (isBlocking && !monitored) {
    return buildBlockResponse(ctx, decision);
  }
  return forwardToOrigin(ctx);
}

export default {
  async fetch(request: Request, env: Env, _ctx: ExecutionContext): Promise<Response> {
    const startedAt = Date.now();
    // Tracked outside the try so the catch block knows whether to fail closed.
    let site: ResolvedSite | null = null;

    try {
      const url = new URL(request.url);
      const host = url.hostname.toLowerCase();

      // -- 1. Shield's own endpoints. Never forwarded to the origin. --
      if (isShieldPath(url.pathname)) {
        return await handleShieldRequest(request, url, env);
      }

      // -- 2. Resolve config. --
      site = await loadSite(host, env, startedAt);
      if (site === null) {
        // An unconfigured hostname is passed through untouched: attaching the route
        // before writing the config must not break the site. Logged once per TTL window
        // so it is visible without flooding the log.
        if (shouldLogUnknownHost(host, startedAt, defaultGlobalConfig.configTtlSeconds)) {
          logEvent({ level: 'info', event: 'host.unconfigured', host });
        }
        return await fetch(request);
      }

      // -- 3. Evaluate. --
      const requestContext = buildContext(request, url, site);
      const decision = await evaluate(requestContext, env);

      // -- 4. Respond. --
      return await respond(requestContext, decision, startedAt);
    } catch (error) {
      logEvent({
        level: 'error',
        event: 'handler.error',
        message: error instanceof Error ? error.message : String(error),
        stack: error instanceof Error ? error.stack : undefined,
      });

      if (site !== null && site.config.failClosed) {
        return buildFailClosedResponse();
      }
      // Fail open. If even this throws there is nothing left to do but let the runtime
      // return its own 5xx.
      return fetch(request);
    }
  },
} satisfies ExportedHandler<Env>;
