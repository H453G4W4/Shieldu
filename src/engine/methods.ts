/**
 * HTTP method rules.
 *
 * TRACE and TRACK enable Cross-Site Tracing; CONNECT has no meaning for an HTTP origin.
 * Sites that only ever serve a read-only front-end can additionally pin an explicit
 * allowed-methods list.
 */

import type { RequestContext } from '../context';
import type { Decision } from '../config/types';

export function evaluateMethods(ctx: RequestContext): Decision | null {
  const { methods } = ctx.site.config;

  if (methods.allowed !== null) {
    // Uppercased at compile time is not worth a cache entry; these lists are tiny.
    for (let i = 0; i < methods.allowed.length; i++) {
      if ((methods.allowed[i] as string).toUpperCase() === ctx.method) return null;
    }
    return {
      ruleId: 'method.notAllowed',
      action: 'block',
      status: 405,
      detail: ctx.method,
    };
  }

  for (let i = 0; i < methods.blocked.length; i++) {
    if ((methods.blocked[i] as string).toUpperCase() === ctx.method) {
      return { ruleId: 'method.blocked', action: 'block', status: 405, detail: ctx.method };
    }
  }
  return null;
}
