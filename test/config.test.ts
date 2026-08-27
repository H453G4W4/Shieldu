import { env } from 'cloudflare:test';
import { beforeEach, describe, expect, it } from 'vitest';
import { defaultSiteConfig } from '../src/config/defaults';
import { loadSite, resetConfigCache } from '../src/config/loader';
import { deepMerge } from '../src/config/merge';
import type { Env } from '../src/config/types';

const testEnv = env as unknown as Env;

beforeEach(async () => {
  resetConfigCache();
  const kv = testEnv.SHIELD_CONFIG;
  if (kv !== undefined) {
    const list = await kv.list();
    await Promise.all(list.keys.map((key) => kv.delete(key.name)));
  }
});

describe('deepMerge', () => {
  it('merges nested objects key by key', () => {
    const merged = deepMerge(defaultSiteConfig, { wordpress: { allowXmlrpc: true } });
    expect(merged.wordpress.allowXmlrpc).toBe(true);
    expect(merged.wordpress.blockUserEnumeration).toBe(
      defaultSiteConfig.wordpress.blockUserEnumeration,
    );
  });

  it('replaces arrays wholesale instead of concatenating', () => {
    const base = deepMerge(defaultSiteConfig, { block: { ip: ['1.1.1.1', '2.2.2.2'] } });
    const merged = deepMerge(base, { block: { ip: ['3.3.3.3'] } });
    expect(merged.block.ip).toEqual(['3.3.3.3']);
  });

  it('lets an explicit null disable a rate limit group', () => {
    const merged = deepMerge(defaultSiteConfig, { rateLimits: { login: null } });
    expect(merged.rateLimits.login).toBeNull();
    expect(merged.rateLimits.xmlrpc).not.toBeNull();
  });

  it('lets an object replace a null slot', () => {
    const merged = deepMerge(defaultSiteConfig, {
      rateLimits: { general: { limit: 200, period: 60 } },
    });
    expect(merged.rateLimits.general).toEqual({ limit: 200, period: 60 });
  });

  it('ignores unknown keys', () => {
    const merged = deepMerge(defaultSiteConfig, { totallyUnknown: true });
    expect('totallyUnknown' in merged).toBe(false);
  });

  it('ignores type mismatches instead of corrupting the config', () => {
    const merged = deepMerge(defaultSiteConfig, {
      mode: 42,
      failClosed: 'yes',
      block: { ip: 'not-an-array' },
    });
    expect(merged.mode).toBe(defaultSiteConfig.mode);
    expect(merged.failClosed).toBe(defaultSiteConfig.failClosed);
    expect(merged.block.ip).toEqual([]);
  });

  it('leaves the base untouched', () => {
    const before = JSON.stringify(defaultSiteConfig);
    deepMerge(defaultSiteConfig, { wordpress: { allowXmlrpc: true }, block: { asn: [1] } });
    expect(JSON.stringify(defaultSiteConfig)).toBe(before);
  });

  it('returns the base for a non-object override', () => {
    expect(deepMerge(defaultSiteConfig, 'nope')).toBe(defaultSiteConfig);
    expect(deepMerge(defaultSiteConfig, undefined)).toBe(defaultSiteConfig);
    expect(deepMerge(defaultSiteConfig, null)).toBe(defaultSiteConfig);
  });
});

describe('loadSite', () => {
  it('resolves a static site entry', async () => {
    const site = await loadSite('example.com', testEnv, Date.now());
    expect(site).not.toBeNull();
    expect(site?.config.type).toBe('wordpress');
  });

  it('is case insensitive on the hostname', async () => {
    const site = await loadSite('WWW.Example.COM', testEnv, Date.now());
    expect(site?.config.type).toBe('wordpress');
  });

  it('returns null for an unconfigured hostname', async () => {
    expect(await loadSite('unknown.invalid', testEnv, Date.now())).toBeNull();
  });

  it('applies a KV override on top of the static entry', async () => {
    await testEnv.SHIELD_CONFIG?.put(
      'site:example.com',
      JSON.stringify({ mode: 'enforce', block: { country: ['RU'] } }),
    );
    const site = await loadSite('example.com', testEnv, Date.now());
    expect(site?.config.mode).toBe('enforce');
    expect(site?.block.countries.has('RU')).toBe(true);
    // The static allow list survives the merge.
    expect(site?.config.allow.ip).toContain('203.0.113.10');
  });

  it('creates a site from a KV-only entry, merged over the defaults', async () => {
    await testEnv.SHIELD_CONFIG?.put(
      'site:kvonly.invalid',
      JSON.stringify({ type: 'wordpress', mode: 'enforce' }),
    );
    const site = await loadSite('kvonly.invalid', testEnv, Date.now());
    expect(site?.config.type).toBe('wordpress');
    expect(site?.config.failClosed).toBe(false);
  });

  it('falls back to the static config when the KV value is malformed', async () => {
    await testEnv.SHIELD_CONFIG?.put('site:example.com', 'this is not json');
    const site = await loadSite('example.com', testEnv, Date.now());
    expect(site).not.toBeNull();
    expect(site?.config.mode).toBe('monitor');
  });

  it('falls back to the static config when KV throws', async () => {
    const brokenEnv = {
      SHIELD_CONFIG: {
        get: () => Promise.reject(new Error('KV is down')),
      },
    } as unknown as Env;
    const site = await loadSite('example.com', brokenEnv, Date.now());
    expect(site).not.toBeNull();
    expect(site?.config.type).toBe('wordpress');
  });

  it('works with no KV binding at all', async () => {
    const site = await loadSite('example.com', {} as Env, Date.now());
    expect(site?.config.type).toBe('wordpress');
  });

  it('serves from the module-scope cache until the TTL expires', async () => {
    const now = Date.now();
    const first = await loadSite('example.com', testEnv, now);
    await testEnv.SHIELD_CONFIG?.put('site:example.com', JSON.stringify({ mode: 'enforce' }));

    const cached = await loadSite('example.com', testEnv, now + 1_000);
    expect(cached).toBe(first);
    expect(cached?.config.mode).toBe('monitor');

    const refreshed = await loadSite('example.com', testEnv, now + 61_000);
    expect(refreshed?.config.mode).toBe('enforce');
  });

  it('caches the "unconfigured" answer too', async () => {
    const now = Date.now();
    expect(await loadSite('later.invalid', testEnv, now)).toBeNull();
    await testEnv.SHIELD_CONFIG?.put('site:later.invalid', JSON.stringify({ mode: 'enforce' }));
    expect(await loadSite('later.invalid', testEnv, now + 1_000)).toBeNull();
    expect(await loadSite('later.invalid', testEnv, now + 61_000)).not.toBeNull();
  });

  it('merges the global allow list into every site', async () => {
    await testEnv.SHIELD_CONFIG?.put(
      'global',
      JSON.stringify({ allow: { ip: ['198.51.100.0/24'] } }),
    );
    const site = await loadSite('example.com', testEnv, Date.now());
    expect(site?.allow.cidrs.some((c) => c.source === '198.51.100.0/24')).toBe(true);
    // and the per-site entry is still there
    expect(site?.allow.cidrs.some((c) => c.source === '203.0.113.10')).toBe(true);
  });
});
