/**
 * End-to-end tests for the fetch handler: monitor mode, block responses, security headers
 * on origin responses, fail-open behaviour and the unknown-host passthrough.
 *
 * The origin is stubbed by replacing the global `fetch`, so no real network is involved
 * and every assertion is about what the Worker itself does.
 */

import { createExecutionContext, env, waitOnExecutionContext } from 'cloudflare:test';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import worker from '../src/index';
import { resetConfigCache } from '../src/config/loader';
import type { Env } from '../src/config/types';

const testEnv = env as unknown as Env;

interface OriginCall {
  url: string;
  method: string;
}

let originCalls: OriginCall[] = [];

/** Replace the global fetch with a stub origin. Returns the recorded calls. */
function stubOrigin(response: () => Response): void {
  vi.stubGlobal('fetch', (input: RequestInfo | URL) => {
    const request = input instanceof Request ? input : new Request(input);
    originCalls.push({ url: request.url, method: request.method });
    return Promise.resolve(response());
  });
}

function okOrigin(): Response {
  return new Response('<html>origin</html>', {
    status: 200,
    headers: { 'Content-Type': 'text/html', 'X-Powered-By': 'PHP/8.2.0' },
  });
}

/** A request whose `cf` getter throws, to force an unexpected error inside the handler. */
function brokenCfRequest(url: string): Request {
  const request = new Request(url, {
    headers: { 'CF-Connecting-IP': '198.51.100.77' },
  });
  Object.defineProperty(request, 'cf', {
    get() {
      throw new Error('cf exploded');
    },
  });
  return request;
}

async function call(url: string, init: RequestInit = {}): Promise<Response> {
  const headers = new Headers(init.headers ?? {});
  if (!headers.has('CF-Connecting-IP')) headers.set('CF-Connecting-IP', '198.51.100.77');
  const request = new Request(url, {
    ...init,
    headers,
    cf: { country: 'US', asn: 64500, asOrganization: 'Example ISP' },
  } as RequestInit);
  const ctx = createExecutionContext();
  const response = await worker.fetch(request, testEnv, ctx);
  await waitOnExecutionContext(ctx);
  return response;
}

beforeEach(async () => {
  originCalls = [];
  resetConfigCache();
  stubOrigin(okOrigin);
  const kv = testEnv.SHIELD_CONFIG;
  if (kv !== undefined) {
    const list = await kv.list();
    await Promise.all(list.keys.map((key) => kv.delete(key.name)));
  }
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('health endpoint', () => {
  it('answers without a token and never reaches the origin', async () => {
    const response = await call('https://example.com/__shield/health');
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ ok: true, version: expect.any(String) });
    expect(originCalls).toHaveLength(0);
  });

  it('answers even for an unconfigured hostname', async () => {
    const response = await call('https://unknown.invalid/__shield/health');
    expect(response.status).toBe(200);
    expect(originCalls).toHaveLength(0);
  });

  it('rejects a non-GET method', async () => {
    const response = await call('https://example.com/__shield/health', { method: 'POST' });
    expect(response.status).toBe(405);
  });

  it('never forwards any /__shield/ path to the origin', async () => {
    const response = await call('https://example.com/__shield/whatever');
    expect(response.status).toBe(404);
    expect(originCalls).toHaveLength(0);
  });
});

describe('unknown hostname', () => {
  it('is forwarded untouched, with no security headers added', async () => {
    const response = await call('https://unknown.invalid/anything');
    expect(response.status).toBe(200);
    expect(originCalls).toHaveLength(1);
    expect(response.headers.get('X-Content-Type-Options')).toBeNull();
    expect(response.headers.get('X-Powered-By')).toBe('PHP/8.2.0');
  });

  it('is forwarded even for a path the shield would normally block', async () => {
    const response = await call('https://unknown.invalid/.env');
    expect(response.status).toBe(200);
    expect(originCalls).toHaveLength(1);
  });
});

describe('monitor mode', () => {
  it('lets a request the rules would block through to the origin', async () => {
    // example.com ships as mode: "monitor" in the static config.
    const response = await call('https://example.com/xmlrpc.php');
    expect(response.status).toBe(200);
    expect(originCalls).toHaveLength(1);
  });

  it('still applies the security headers in monitor mode', async () => {
    const response = await call('https://example.com/xmlrpc.php');
    expect(response.headers.get('X-Content-Type-Options')).toBe('nosniff');
  });
});

describe('enforce mode', () => {
  beforeEach(async () => {
    await testEnv.SHIELD_CONFIG?.put('site:example.com', JSON.stringify({ mode: 'enforce' }));
    resetConfigCache();
  });

  it('blocks with a 403 and never touches the origin', async () => {
    const response = await call('https://example.com/xmlrpc.php');
    expect(response.status).toBe(403);
    expect(originCalls).toHaveLength(0);
    expect(response.headers.get('Cache-Control')).toContain('no-store');
  });

  it('returns JSON for a REST-shaped request', async () => {
    const response = await call('https://example.com/wp-json/wp/v2/users');
    expect(response.status).toBe(403);
    expect(response.headers.get('Content-Type')).toContain('application/json');
    expect(await response.json()).toMatchObject({ error: 'forbidden' });
  });

  it('returns HTML for a browser request', async () => {
    const response = await call('https://example.com/.env');
    expect(response.headers.get('Content-Type')).toContain('text/html');
    expect(await response.text()).toContain('Request blocked');
  });

  it('does not leak the rule id unless debugHeaders is on', async () => {
    const withoutDebug = await call('https://example.com/.env');
    expect(withoutDebug.headers.get('X-Shield-Rule')).toBeNull();

    await testEnv.SHIELD_CONFIG?.put(
      'site:example.com',
      JSON.stringify({ mode: 'enforce', debugHeaders: true }),
    );
    resetConfigCache();
    const withDebug = await call('https://example.com/.env');
    expect(withDebug.headers.get('X-Shield-Rule')).toBe('path.sensitiveFile');
  });

  it('still lets admin-ajax.php through', async () => {
    const response = await call('https://example.com/wp-admin/admin-ajax.php', { method: 'POST' });
    expect(response.status).toBe(200);
    expect(originCalls).toHaveLength(1);
  });
});

describe('origin responses', () => {
  it('gets the security headers and keeps the body', async () => {
    const response = await call('https://example.com/');
    expect(response.status).toBe(200);
    expect(await response.text()).toBe('<html>origin</html>');
    expect(response.headers.get('X-Content-Type-Options')).toBe('nosniff');
    expect(response.headers.get('X-Powered-By')).toBeNull();
  });

  it('forwards the original method and URL to the origin', async () => {
    await call('https://example.com/contact?ref=1', { method: 'POST' });
    expect(originCalls[0]).toEqual({ url: 'https://example.com/contact?ref=1', method: 'POST' });
  });
});

describe('fail open', () => {
  it('forwards to the origin when the handler throws', async () => {
    // `loadSite` already swallows KV failures, so break something the handler does not
    // guard: reading request.cf while building the request context.
    const request = brokenCfRequest('https://example.com/xmlrpc.php');

    const ctx = createExecutionContext();
    const response = await worker.fetch(request, testEnv, ctx);
    await waitOnExecutionContext(ctx);

    // The request would have been blocked in enforce mode; failing open forwards it.
    expect(response.status).toBe(200);
    expect(originCalls).toHaveLength(1);
  });

  it('returns 503 instead when the site is configured failClosed', async () => {
    await testEnv.SHIELD_CONFIG?.put(
      'site:example.com',
      JSON.stringify({ mode: 'enforce', failClosed: true }),
    );
    resetConfigCache();

    const request = brokenCfRequest('https://example.com/');
    const ctx = createExecutionContext();
    const response = await worker.fetch(request, testEnv, ctx);
    await waitOnExecutionContext(ctx);

    expect(response.status).toBe(503);
    expect(response.headers.get('Retry-After')).toBe('30');
    expect(originCalls).toHaveLength(0);
  });
});
