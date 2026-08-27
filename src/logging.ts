/**
 * Structured logging. One JSON line per decision, written with `console.log` so it lands
 * in Workers Logs (enabled via `observability` in wrangler.jsonc) and in `wrangler tail`.
 *
 * Keep the shape stable: dashboards and log queries are built on these field names.
 */

import type { RequestContext } from './context';
import type { Decision, SiteMode } from './config/types';

const MAX_UA_LENGTH = 120;

export interface ShieldLogRecord {
  /** Always "shield", so the lines are trivially greppable among other output. */
  src: 'shield';
  ts: string;
  host: string;
  method: string;
  path: string;
  ip: string;
  country: string;
  asn: number;
  asOrg: string;
  ua: string;
  ruleId: string;
  action: string;
  /** True when the action was downgraded to log-only by monitor mode. */
  monitored: boolean;
  mode: SiteMode;
  status: number;
  durationMs: number;
  detail?: string;
}

function truncate(value: string, max: number): string {
  return value.length > max ? `${value.slice(0, max)}...` : value;
}

/**
 * Emit one decision line.
 *
 * `durationMs` is measured with `Date.now()`, which the Workers runtime only advances on
 * I/O. For a request the shield blocks without touching the origin it is therefore
 * usually 0. That is expected, not a bug — use it as a coarse signal only.
 */
export function logDecision(
  ctx: RequestContext,
  decision: Decision,
  options: { monitored: boolean; durationMs: number },
): void {
  const record: ShieldLogRecord = {
    src: 'shield',
    ts: new Date().toISOString(),
    host: ctx.host,
    method: ctx.method,
    path: truncate(ctx.path, 512),
    ip: ctx.ip,
    country: ctx.country,
    asn: ctx.asn,
    asOrg: truncate(ctx.asOrg, 64),
    ua: truncate(ctx.ua, MAX_UA_LENGTH),
    ruleId: decision.ruleId,
    action: decision.action,
    monitored: options.monitored,
    mode: ctx.site.config.mode,
    status: decision.status,
    durationMs: options.durationMs,
  };
  if (decision.detail !== undefined) record.detail = decision.detail;
  console.log(JSON.stringify(record));
}

/** Emit a line that is not tied to a resolved site (unknown host, internal error). */
export function logEvent(fields: Record<string, unknown>): void {
  console.log(JSON.stringify({ src: 'shield', ts: new Date().toISOString(), ...fields }));
}
