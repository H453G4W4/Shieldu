import { createExecutionContext, env, waitOnExecutionContext } from 'cloudflare:test';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import worker from '../src/index';
import { resetConfigCache } from '../src/config/loader';
import type { Env } from '../src/config/types';
import { __test } from '../src/admin/api';

const testEnv = env as unknown as Env;
const TOKEN = 'test-admin-token';

async function api(
  path: string,
  init: RequestInit & { token?: string | null; ip?: string; envOverride?: Env } = {},
): Promise<Response> {
  const headers = new Headers(init.headers ?? {});
  const token = init.token === undefined ? TOKEN : init.token;
  if (token !== null) headers.set('Authorization', `Bearer ${token}`);
  headers.set('CF-Connecting-IP', init.ip ?? '203.0.113.5');
  if (init.body !== undefined) headers.set('Content-Type', 'application/json');

  const request = new Request(`https://example.com${path}`, {
    method: init.method ?? 'GET',
    headers,
    body: init.body ?? null,
    cf: { country: 'US', asn: 64500, asOrganization: 'Example ISP' },
  } as RequestInit);

  const ctx = createExecutionContext();
  const response = await worker.fetch(request, init.envOverride ?? testEnv, ctx);
  await waitOnExecutionContext(ctx);
  return response;
}

beforeEach(async () => {
  resetConfigCache();
  // The admin API is never allowed to reach the origin; stub fetch so a regression shows
  // up as a failed assertion rather than a network error.
  vi.stubGlobal('fetch', () => Promise.resolve(new Response('origin', { status: 200 })));
  const kv = testEnv.SHIELD_CONFIG;
  if (kv !== undefined) {
    const list = await kv.list();
    await Promise.all(list.keys.map((key) => kv.delete(key.name)));
  }
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('timingSafeEqual', () => {
  it('compares equal strings as equal', () => {
    expect(__test.timingSafeEqual('abc', 'abc')).toBe(true);
    expect(__test.timingSafeEqual('', '')).toBe(true);
  });

  it('rejects different strings, including prefixes', () => {
    expect(__test.timingSafeEqual('abc', 'abd')).toBe(false);
    expect(__test.timingSafeEqual('abc', 'ab')).toBe(false);
    expect(__test.timingSafeEqual('ab', 'abc')).toBe(false);
    expect(__test.timingSafeEqual('abc', '')).toBe(false);
  });

  it('handles non-ASCII without throwing', () => {
    expect(__test.timingSafeEqual('مرحبا', 'مرحبا')).toBe(true);
    expect(__test.timingSafeEqual('مرحبا', 'مرحبب')).toBe(false);
  });
});

describe('normalizeHost', () => {
  it('lowercases and trims', () => {
    expect(__test.normalizeHost('  Example.COM ')).toBe('example.com');
  });

  it('rejects anything that is not a bare hostname', () => {
    for (const value of [
      null,
      '',
      '   ',
      'https://example.com',
      'example.com/wp-admin',
      'example.com:8080',
      'exa mple.com',
      `${'a'.repeat(254)}.com`,
    ]) {
      expect(__test.normalizeHost(value), String(value)).toBeNull();
    }
  });
});

describe('authentication', () => {
  it('rejects a request with no token', async () => {
    const response = await api('/__shield/api/config?host=example.com', { token: null });
    expect(response.status).toBe(401);
  });

  it('rejects a wrong token', async () => {
    const response = await api('/__shield/api/config?host=example.com', { token: 'nope' });
    expect(response.status).toBe(401);
  });

  it('rejects a token that is a prefix of the real one', async () => {
    const response = await api('/__shield/api/config?host=example.com', {
      token: TOKEN.slice(0, -1),
    });
    expect(response.status).toBe(401);
  });

  it('reports the API as disabled when no token is configured', async () => {
    const noToken = { ...testEnv, SHIELD_ADMIN_TOKEN: undefined } as Env;
    const response = await api('/__shield/api/config?host=example.com', { envOverride: noToken });
    expect(response.status).toBe(503);
    expect(await response.json()).toMatchObject({ error: 'admin_api_disabled' });
  });

  it('honours the admin IP allow list', async () => {
    await testEnv.SHIELD_CONFIG?.put(
      'global',
      JSON.stringify({ adminAllowIp: ['198.51.100.0/24'] }),
    );
    resetConfigCache();

    const denied = await api('/__shield/api/config?host=example.com', { ip: '203.0.113.5' });
    expect(denied.status).toBe(403);

    const allowed = await api('/__shield/api/config?host=example.com', { ip: '198.51.100.9' });
    expect(allowed.status).toBe(200);
  });
});

describe('GET /__shield/api/config', () => {
  it('returns the effective merged config', async () => {
    const response = await api('/__shield/api/config?host=example.com');
    expect(response.status).toBe(200);
    const body = (await response.json()) as { configured: boolean; config: { type: string } };
    expect(body.configured).toBe(true);
    expect(body.config.type).toBe('wordpress');
  });

  it('reports an unconfigured hostname', async () => {
    const response = await api('/__shield/api/config?host=nowhere.invalid');
    expect(await response.json()).toMatchObject({ configured: false, config: null });
  });

  it('rejects a malformed hostname', async () => {
    const response = await api('/__shield/api/config?host=not%20a%20host');
    expect(response.status).toBe(400);
  });
});

describe('POST /__shield/api/mode', () => {
  it('switches a site to enforce and takes effect immediately', async () => {
    const response = await api('/__shield/api/mode', {
      method: 'POST',
      body: JSON.stringify({ host: 'example.com', mode: 'enforce' }),
    });
    expect(response.status).toBe(200);

    const config = await api('/__shield/api/config?host=example.com');
    const body = (await config.json()) as { config: { mode: string } };
    expect(body.config.mode).toBe('enforce');
  });

  it('rejects an invalid mode', async () => {
    const response = await api('/__shield/api/mode', {
      method: 'POST',
      body: JSON.stringify({ host: 'example.com', mode: 'whatever' }),
    });
    expect(response.status).toBe(400);
  });

  it('rejects a malformed body', async () => {
    const response = await api('/__shield/api/mode', { method: 'POST', body: 'not json' });
    expect(response.status).toBe(400);
  });

  it('can also switch countryMode', async () => {
    await api('/__shield/api/mode', {
      method: 'POST',
      body: JSON.stringify({ host: 'example.com', countryMode: 'allow' }),
    });
    const config = await api('/__shield/api/config?host=example.com');
    const body = (await config.json()) as { config: { countryMode: string } };
    expect(body.config.countryMode).toBe('allow');
  });
});

describe('POST /__shield/api/list', () => {
  it('adds and removes an IP in the block list', async () => {
    const added = await api('/__shield/api/list', {
      method: 'POST',
      body: JSON.stringify({
        host: 'example.com',
        list: 'block',
        field: 'ip',
        op: 'add',
        values: ['198.51.100.7', '192.0.2.0/24'],
      }),
    });
    expect(added.status).toBe(200);
    expect(await added.json()).toMatchObject({ values: ['198.51.100.7', '192.0.2.0/24'] });

    const removed = await api('/__shield/api/list', {
      method: 'POST',
      body: JSON.stringify({
        host: 'example.com',
        list: 'block',
        field: 'ip',
        op: 'remove',
        values: ['198.51.100.7'],
      }),
    });
    expect(await removed.json()).toMatchObject({ values: ['192.0.2.0/24'] });
  });

  it('starts from the static list when adding to an allow list', async () => {
    const response = await api('/__shield/api/list', {
      method: 'POST',
      body: JSON.stringify({
        host: 'example.com',
        list: 'allow',
        field: 'ip',
        op: 'add',
        values: ['198.51.100.7'],
      }),
    });
    const body = (await response.json()) as { values: string[] };
    // The static entry for example.com already allows 203.0.113.10.
    expect(body.values).toContain('203.0.113.10');
    expect(body.values).toContain('198.51.100.7');
  });

  it('does not create duplicates', async () => {
    for (let i = 0; i < 3; i++) {
      await api('/__shield/api/list', {
        method: 'POST',
        body: JSON.stringify({
          host: 'example.com',
          list: 'block',
          field: 'asn',
          op: 'add',
          values: [14061],
        }),
      });
    }
    const response = await api('/__shield/api/list', {
      method: 'POST',
      body: JSON.stringify({
        host: 'example.com',
        list: 'block',
        field: 'asn',
        op: 'add',
        values: [14061],
      }),
    });
    expect(await response.json()).toMatchObject({ values: [14061] });
  });

  it('normalises country codes to uppercase', async () => {
    const response = await api('/__shield/api/list', {
      method: 'POST',
      body: JSON.stringify({
        host: 'example.com',
        list: 'block',
        field: 'country',
        op: 'add',
        values: ['ru', 'cn'],
      }),
    });
    expect(await response.json()).toMatchObject({ values: ['RU', 'CN'] });
  });

  it('rejects invalid input instead of silently dropping it', async () => {
    const cases: Array<[Record<string, unknown>, string]> = [
      [{ list: 'nope', field: 'ip', op: 'add', values: [] }, 'invalid_list'],
      [{ list: 'block', field: 'nope', op: 'add', values: [] }, 'invalid_field'],
      [{ list: 'block', field: 'ip', op: 'nope', values: [] }, 'invalid_op'],
      [{ list: 'block', field: 'ip', op: 'add', values: 'x' }, 'invalid_values'],
      [{ list: 'block', field: 'ip', op: 'add', values: ['garbage'] }, 'invalid_ip'],
      [{ list: 'block', field: 'asn', op: 'add', values: ['abc'] }, 'invalid_asn'],
      [{ list: 'block', field: 'country', op: 'add', values: ['MOROCCO'] }, 'invalid_country'],
    ];
    for (const [body, error] of cases) {
      const response = await api('/__shield/api/list', {
        method: 'POST',
        body: JSON.stringify({ host: 'example.com', ...body }),
      });
      expect(response.status, error).toBe(400);
      expect(await response.json(), error).toMatchObject({ error });
    }
  });

  it('makes a new block entry take effect on the next request', async () => {
    await api('/__shield/api/mode', {
      method: 'POST',
      body: JSON.stringify({ host: 'example.com', mode: 'enforce' }),
    });
    await api('/__shield/api/list', {
      method: 'POST',
      body: JSON.stringify({
        host: 'example.com',
        list: 'block',
        field: 'ip',
        op: 'add',
        values: ['198.51.100.7'],
      }),
    });
    resetConfigCache();

    const request = new Request('https://example.com/', {
      headers: { 'CF-Connecting-IP': '198.51.100.7' },
      cf: { country: 'US', asn: 64500 },
    } as RequestInit);
    const ctx = createExecutionContext();
    const response = await worker.fetch(request, testEnv, ctx);
    await waitOnExecutionContext(ctx);
    expect(response.status).toBe(403);
  });
});

describe('/__shield/api/override', () => {
  it('reads back the raw override', async () => {
    await api('/__shield/api/mode', {
      method: 'POST',
      body: JSON.stringify({ host: 'example.com', mode: 'enforce' }),
    });
    const response = await api('/__shield/api/override?host=example.com');
    expect(await response.json()).toMatchObject({ override: { mode: 'enforce' } });
  });

  it('deletes the override and falls back to the static config', async () => {
    await api('/__shield/api/mode', {
      method: 'POST',
      body: JSON.stringify({ host: 'example.com', mode: 'enforce' }),
    });
    const deleted = await api('/__shield/api/override?host=example.com', { method: 'DELETE' });
    expect(deleted.status).toBe(200);

    const config = await api('/__shield/api/config?host=example.com');
    const body = (await config.json()) as { config: { mode: string } };
    expect(body.config.mode).toBe('monitor');
  });

  it('rejects an unsupported method', async () => {
    const response = await api('/__shield/api/override?host=example.com', { method: 'PUT' });
    expect(response.status).toBe(405);
  });
});

describe('unknown routes', () => {
  it('returns 404 for an unknown api path', async () => {
    const response = await api('/__shield/api/nope');
    expect(response.status).toBe(404);
  });
});
