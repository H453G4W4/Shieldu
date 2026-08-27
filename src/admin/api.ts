/**
 * The shield's own endpoints, under `/__shield/`. These are never forwarded to the origin.
 *
 *   GET    /__shield/health                      -- no auth, returns {ok, version}
 *   GET    /__shield/api/config?host=<host>      -- effective merged config
 *   GET    /__shield/api/override?host=<host>    -- raw KV override, or null
 *   DELETE /__shield/api/override?host=<host>    -- delete the KV override
 *   POST   /__shield/api/mode                    -- {host, mode}
 *   POST   /__shield/api/list                    -- {host, list, field, op, values}
 *
 * Auth: `Authorization: Bearer <SHIELD_ADMIN_TOKEN>`, compared in constant time, plus an
 * optional IP allow list (`global.adminAllowIp` in KV) and a rate limit.
 *
 * Cache note: a write invalidates the module-scope cache in THIS isolate only. Other
 * isolates keep serving the previous config until their TTL expires (default 60 s).
 */

import { CHALLENGE_SUBMIT_PATH, handleChallengeSubmission } from '../actions/challenge';
import { defaultSiteConfig, SHIELD_VERSION } from '../config/defaults';
import { invalidateSite, loadSite, staticSiteFor } from '../config/loader';
import { deepMerge } from '../config/merge';
import type { CountryMode, Env, SiteConfigOverride, SiteMode } from '../config/types';
import { compileCidrList, ipInAnyCidr, invalidCidrEntries, parseIp } from '../engine/ip';
import { logEvent } from '../logging';

const SHIELD_PREFIX = '/__shield/';
const HEALTH_PATH = '/__shield/health';

/** True for any path the shield answers itself. */
export function isShieldPath(pathname: string): boolean {
  return pathname === '/__shield' || pathname.startsWith(SHIELD_PREFIX);
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
    },
  });
}

/**
 * Constant-time string comparison.
 *
 * `crypto.subtle.timingSafeEqual` is not available in all Workers compatibility modes, so
 * this does the classic accumulate-XOR over the UTF-8 bytes. Lengths are compared by
 * padding the loop to the longer of the two so that a length mismatch does not short
 * circuit.
 */
function timingSafeEqual(a: string, b: string): boolean {
  const encoder = new TextEncoder();
  const left = encoder.encode(a);
  const right = encoder.encode(b);
  const length = Math.max(left.length, right.length);
  let diff = left.length ^ right.length;
  for (let i = 0; i < length; i++) {
    diff |= (left[i] ?? 0) ^ (right[i] ?? 0);
  }
  return diff === 0;
}

interface AuthFailure {
  response: Response;
}

async function authorize(request: Request, env: Env): Promise<AuthFailure | null> {
  const token = env.SHIELD_ADMIN_TOKEN;
  if (token === undefined || token === '') {
    // Without a token the API is disabled outright rather than left open.
    return { response: json({ error: 'admin_api_disabled' }, 503) };
  }

  const ip = request.headers.get('CF-Connecting-IP') ?? '';

  // Optional IP allow list, read from the global config in KV.
  let adminAllowIp: string[] = [];
  try {
    const raw = await env.SHIELD_CONFIG?.get('global', 'json');
    const list = (raw as { adminAllowIp?: unknown } | null)?.adminAllowIp;
    if (Array.isArray(list)) adminAllowIp = list.filter((v): v is string => typeof v === 'string');
  } catch {
    adminAllowIp = [];
  }
  if (adminAllowIp.length > 0) {
    const allowed = ipInAnyCidr(ip === '' ? null : parseIp(ip), compileCidrList(adminAllowIp));
    if (!allowed) {
      logEvent({ level: 'warn', event: 'admin.ipDenied', ip });
      return { response: json({ error: 'forbidden' }, 403) };
    }
  }

  // Rate limit admin auth attempts using the general binding, keyed separately from
  // ordinary traffic so a brute-force attempt cannot be hidden in normal request volume.
  try {
    const limiter = env.RL_GENERAL;
    if (limiter !== undefined) {
      const result = await limiter.limit({ key: `admin:${ip === '' ? 'unknown' : ip}` });
      if (!result.success) {
        return {
          response: new Response(JSON.stringify({ error: 'too_many_requests' }), {
            status: 429,
            headers: {
              'Content-Type': 'application/json; charset=utf-8',
              'Cache-Control': 'no-store',
              'Retry-After': '60',
            },
          }),
        };
      }
    }
  } catch {
    // A broken limiter must not lock the operator out of their own admin API.
  }

  const header = request.headers.get('Authorization') ?? '';
  const presented = header.startsWith('Bearer ') ? header.slice(7) : '';
  if (!timingSafeEqual(presented, token)) {
    logEvent({ level: 'warn', event: 'admin.authFailed', ip });
    return { response: json({ error: 'unauthorized' }, 401) };
  }

  return null;
}

function normalizeHost(value: string | null): string | null {
  if (value === null) return null;
  const host = value.trim().toLowerCase();
  if (host === '' || host.length > 253) return null;
  // Hostnames only: no scheme, no path, no port.
  if (!/^[a-z0-9.-]+$/.test(host)) return null;
  return host;
}

async function readOverride(env: Env, host: string): Promise<SiteConfigOverride> {
  const kv = env.SHIELD_CONFIG;
  if (kv === undefined) return {};
  try {
    const value = await kv.get(`site:${host}`, 'json');
    return value === null || typeof value !== 'object' ? {} : (value as SiteConfigOverride);
  } catch {
    return {};
  }
}

async function writeOverride(
  env: Env,
  host: string,
  override: SiteConfigOverride,
): Promise<Response | null> {
  const kv = env.SHIELD_CONFIG;
  if (kv === undefined) return json({ error: 'kv_not_bound' }, 503);
  await kv.put(`site:${host}`, JSON.stringify(override));
  invalidateSite(host);
  return null;
}

const LIST_NAMES = new Set(['allow', 'block']);
const LIST_FIELDS = new Set(['ip', 'cidr', 'asn', 'country']);

interface ListRequestBody {
  host?: unknown;
  list?: unknown;
  field?: unknown;
  op?: unknown;
  values?: unknown;
}

/** POST /__shield/api/list -- add or remove entries in an allow/block list. */
async function handleListWrite(request: Request, env: Env): Promise<Response> {
  let body: ListRequestBody;
  try {
    body = (await request.json()) as ListRequestBody;
  } catch {
    return json({ error: 'invalid_json' }, 400);
  }

  const host = normalizeHost(typeof body.host === 'string' ? body.host : null);
  if (host === null) return json({ error: 'invalid_host' }, 400);

  const list = typeof body.list === 'string' ? body.list : '';
  const field = typeof body.field === 'string' ? body.field : '';
  const op = typeof body.op === 'string' ? body.op : '';
  if (!LIST_NAMES.has(list)) return json({ error: 'invalid_list' }, 400);
  if (!LIST_FIELDS.has(field)) return json({ error: 'invalid_field' }, 400);
  if (op !== 'add' && op !== 'remove') return json({ error: 'invalid_op' }, 400);
  if (!Array.isArray(body.values)) return json({ error: 'invalid_values' }, 400);

  // Validate before writing: a malformed CIDR silently dropped at compile time would look
  // like the API accepted a rule that never fires.
  let values: (string | number)[];
  if (field === 'asn') {
    const asns = body.values.map((v) => Number(v));
    if (asns.some((v) => !Number.isInteger(v) || v <= 0)) return json({ error: 'invalid_asn' }, 400);
    values = asns;
  } else if (field === 'country') {
    const codes = body.values.map((v) => String(v).trim().toUpperCase());
    if (codes.some((v) => !/^[A-Z]{2}$/.test(v))) return json({ error: 'invalid_country' }, 400);
    values = codes;
  } else {
    const entries = body.values.map((v) => String(v).trim());
    const invalid = invalidCidrEntries(entries);
    if (invalid.length > 0) return json({ error: 'invalid_ip', invalid }, 400);
    values = entries;
  }

  const override = await readOverride(env, host);
  const container = ((override as Record<string, unknown>)[list] ?? {}) as Record<string, unknown>;

  // The effective current value: the static config plus whatever the override already has.
  const staticEntry = staticSiteFor(host) ?? defaultSiteConfig;
  const staticList = (staticEntry as unknown as Record<string, Record<string, unknown>>)[list];
  const currentRaw = container[field] ?? staticList?.[field] ?? [];
  const current = Array.isArray(currentRaw) ? currentRaw : [];

  const next =
    op === 'add'
      ? Array.from(new Set([...current, ...values]))
      : current.filter((entry) => !values.some((value) => String(value) === String(entry)));

  container[field] = next;
  (override as Record<string, unknown>)[list] = container;

  const failure = await writeOverride(env, host, override);
  if (failure !== null) return failure;

  logEvent({ level: 'info', event: 'admin.listWrite', host, list, field, op, count: values.length });
  return json({ ok: true, host, list, field, values: next });
}

interface ModeRequestBody {
  host?: unknown;
  mode?: unknown;
  countryMode?: unknown;
}

/** POST /__shield/api/mode -- switch a site between monitor and enforce. */
async function handleModeWrite(request: Request, env: Env): Promise<Response> {
  let body: ModeRequestBody;
  try {
    body = (await request.json()) as ModeRequestBody;
  } catch {
    return json({ error: 'invalid_json' }, 400);
  }

  const host = normalizeHost(typeof body.host === 'string' ? body.host : null);
  if (host === null) return json({ error: 'invalid_host' }, 400);

  const override = await readOverride(env, host);
  const record = override as Record<string, unknown>;

  if (body.mode !== undefined) {
    const mode = body.mode;
    if (mode !== 'monitor' && mode !== 'enforce') return json({ error: 'invalid_mode' }, 400);
    record['mode'] = mode satisfies SiteMode;
  }
  if (body.countryMode !== undefined) {
    const countryMode = body.countryMode;
    if (countryMode !== 'block' && countryMode !== 'allow') {
      return json({ error: 'invalid_country_mode' }, 400);
    }
    record['countryMode'] = countryMode satisfies CountryMode;
  }

  const failure = await writeOverride(env, host, override);
  if (failure !== null) return failure;

  logEvent({ level: 'info', event: 'admin.modeWrite', host, mode: record['mode'] });
  return json({ ok: true, host, mode: record['mode'], countryMode: record['countryMode'] });
}

/** GET /__shield/api/config -- the effective merged config for a hostname. */
async function handleConfigRead(url: URL, env: Env): Promise<Response> {
  const host = normalizeHost(url.searchParams.get('host'));
  if (host === null) return json({ error: 'invalid_host' }, 400);

  // Bypass the cache so an operator immediately sees what they just wrote.
  invalidateSite(host);
  const site = await loadSite(host, env, Date.now());
  if (site === null) return json({ host, configured: false, config: null });
  return json({ host, configured: true, config: site.config });
}

async function handleApi(request: Request, url: URL, env: Env): Promise<Response> {
  const route = url.pathname.slice('/__shield/api'.length);

  if (route === '/config' && request.method === 'GET') return handleConfigRead(url, env);

  if (route === '/override') {
    const host = normalizeHost(url.searchParams.get('host'));
    if (host === null) return json({ error: 'invalid_host' }, 400);
    if (request.method === 'GET') {
      return json({ host, override: await readOverride(env, host) });
    }
    if (request.method === 'DELETE') {
      const kv = env.SHIELD_CONFIG;
      if (kv === undefined) return json({ error: 'kv_not_bound' }, 503);
      await kv.delete(`site:${host}`);
      invalidateSite(host);
      logEvent({ level: 'info', event: 'admin.overrideDeleted', host });
      return json({ ok: true, host });
    }
    return json({ error: 'method_not_allowed' }, 405);
  }

  if (route === '/list' && request.method === 'POST') return handleListWrite(request, env);
  if (route === '/mode' && request.method === 'POST') return handleModeWrite(request, env);

  return json({ error: 'not_found' }, 404);
}

/** Entry point for every `/__shield/*` request. */
export async function handleShieldRequest(
  request: Request,
  url: URL,
  env: Env,
): Promise<Response> {
  if (url.pathname === HEALTH_PATH) {
    if (request.method !== 'GET' && request.method !== 'HEAD') {
      return json({ error: 'method_not_allowed' }, 405);
    }
    return json({ ok: true, version: SHIELD_VERSION });
  }

  // The Turnstile callback is unauthenticated by design: it is the visitor's browser
  // posting a token, not an operator.
  if (url.pathname === CHALLENGE_SUBMIT_PATH) {
    const site = await loadSite(url.hostname.toLowerCase(), env, Date.now());
    const config = site?.config.challenge ?? defaultSiteConfig.challenge;
    if (!config.enabled) return json({ error: 'not_found' }, 404);
    return handleChallengeSubmission(request, env, config, Date.now());
  }

  if (!url.pathname.startsWith('/__shield/api')) return json({ error: 'not_found' }, 404);

  const failure = await authorize(request, env);
  if (failure !== null) return failure.response;

  try {
    return await handleApi(request, url, env);
  } catch (error) {
    logEvent({
      level: 'error',
      event: 'admin.error',
      message: error instanceof Error ? error.message : String(error),
    });
    return json({ error: 'internal_error' }, 500);
  }
}

/** Exported for tests. */
export const __test = { timingSafeEqual, normalizeHost, deepMerge };
