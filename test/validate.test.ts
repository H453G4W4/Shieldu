/**
 * Guard rail for hand-written configuration.
 *
 * The first block is the one that matters day to day: it runs the validator over the real
 * `src/config/sites.ts`. Add a site, run `npm test`, and a typo that would have failed
 * open at runtime fails the build instead.
 */

import { describe, expect, it } from 'vitest';
import { defaultSiteConfig } from '../src/config/defaults';
import { deepMerge } from '../src/config/merge';
import { sites } from '../src/config/sites';
import type { DeepPartial, SiteConfig } from '../src/config/types';
import { formatProblems, validateSiteConfig, validateSites } from '../src/config/validate';

const resolvedSites: SiteConfig[] = sites.map((entry) => deepMerge(defaultSiteConfig, entry));

function check(overrides: DeepPartial<SiteConfig>): string[] {
  const config = deepMerge(defaultSiteConfig, { hosts: ['example.com'], ...overrides });
  return validateSiteConfig(config, 'site').map((problem) => problem.path);
}

describe('src/config/sites.ts', () => {
  it('has no configuration problems', () => {
    const problems = validateSites(resolvedSites);
    expect(problems.length === 0 ? '' : `\n${formatProblems(problems)}\n`).toBe('');
  });

  it('declares at least one site', () => {
    expect(resolvedSites.length).toBeGreaterThan(0);
  });
});

describe('validateSites', () => {
  it('flags a hostname claimed by two entries', () => {
    const a = deepMerge(defaultSiteConfig, { hosts: ['dup.example'] });
    const b = deepMerge(defaultSiteConfig, { hosts: ['dup.example'] });
    const problems = validateSites([a, b]);
    expect(problems).toHaveLength(1);
    expect(problems[0]?.path).toBe('sites[1].hosts[0]');
    expect(problems[0]?.message).toContain('sites[0]');
  });

  it('accepts distinct hostnames', () => {
    const a = deepMerge(defaultSiteConfig, { hosts: ['a.example'] });
    const b = deepMerge(defaultSiteConfig, { hosts: ['b.example'] });
    expect(validateSites([a, b])).toHaveLength(0);
  });
});

describe('hosts', () => {
  it('rejects an entry with no hosts', () => {
    expect(check({ hosts: [] })).toEqual(['site.hosts']);
  });

  it('rejects a host that is not a bare lowercase hostname', () => {
    for (const host of [
      'Example.com',
      'https://example.com',
      'example.com/wp-admin',
      'example.com:8443',
      '*.example.com',
      'exa mple.com',
      '-example.com',
      'example-.com',
    ]) {
      expect(check({ hosts: [host] }), host).toEqual(['site.hosts[0]']);
    }
  });

  it('accepts ordinary hostnames', () => {
    for (const host of ['example.com', 'www.example.com', 'a.b.c.example.co.uk', 'x1-y2.example']) {
      expect(check({ hosts: [host] }), host).toEqual([]);
    }
  });
});

describe('allow and block lists', () => {
  it('flags an IP entry that would be dropped silently', () => {
    expect(check({ block: { ip: ['203.0.113.0/24', '203.0.113.'] } })).toEqual([
      'site.block.ip[1]',
    ]);
    expect(check({ allow: { cidr: ['not-an-ip'] } })).toEqual(['site.allow.cidr[0]']);
  });

  it('flags a bad country code', () => {
    expect(check({ block: { country: ['RU', 'morocco'] } })).toEqual(['site.block.country[1]']);
    expect(check({ block: { country: ['ru'] } })).toEqual(['site.block.country[0]']);
  });

  it('flags a bad ASN', () => {
    expect(check({ block: { asn: [14061, 0] } })).toEqual(['site.block.asn[1]']);
    expect(check({ block: { asn: [-1] } })).toEqual(['site.block.asn[0]']);
  });
});

describe('WordPress login allow list', () => {
  // This is the silent fail-open the validator exists to catch: every entry is dropped at
  // compile time, the list looks absent, and an absent list lets everyone through.
  it('flags a malformed login IP allow list', () => {
    expect(check({ wordpress: { loginAllowlistIp: ['203.0.113.10/33'] } })).toEqual([
      'site.wordpress.loginAllowlistIp[0]',
    ]);
  });

  it('flags a malformed login country allow list', () => {
    expect(check({ wordpress: { loginAllowlistCountry: ['ma'] } })).toEqual([
      'site.wordpress.loginAllowlistCountry[0]',
    ]);
  });

  it('accepts a valid login allow list', () => {
    expect(
      check({
        wordpress: {
          loginAllowlistIp: ['203.0.113.10', '2001:db8::/32'],
          loginAllowlistCountry: ['MA', 'FR'],
        },
      }),
    ).toEqual([]);
  });
});

describe('countryMode', () => {
  it('flags allow mode with an empty allow list', () => {
    expect(check({ countryMode: 'allow' })).toEqual(['site.countryMode']);
  });

  it('accepts allow mode with a populated list', () => {
    expect(check({ countryMode: 'allow', allow: { country: ['MA'] } })).toEqual([]);
  });

  it('does not complain about block mode with an empty list', () => {
    expect(check({ countryMode: 'block' })).toEqual([]);
  });
});

describe('rate limits', () => {
  it('flags a period Cloudflare does not accept', () => {
    expect(check({ rateLimits: { login: { limit: 5, period: 30 as 10 } } })).toEqual([
      'site.rateLimits.login.period',
    ]);
  });

  it('flags a non-positive limit', () => {
    expect(check({ rateLimits: { login: { limit: 0, period: 60 } } })).toEqual([
      'site.rateLimits.login.limit',
    ]);
  });

  it('flags a non-positive retryAfterSeconds', () => {
    expect(
      check({ rateLimits: { login: { limit: 5, period: 60, retryAfterSeconds: 0 } } }),
    ).toEqual(['site.rateLimits.login.retryAfterSeconds']);
  });

  it('ignores a disabled group', () => {
    expect(check({ rateLimits: { login: null, xmlrpc: null, comments: null } })).toEqual([]);
  });
});

describe('paths, methods and user agents', () => {
  it('flags a path entry that can never match', () => {
    expect(check({ paths: { extraBlockedPrefixes: ['internal/'] } })).toEqual([
      'site.paths.extraBlockedPrefixes[0]',
    ]);
    expect(check({ paths: { extraBlockedPrefixes: ['/Internal/'] } })).toEqual([
      'site.paths.extraBlockedPrefixes[0]',
    ]);
    expect(check({ paths: { extraAllowedPaths: ['/WP-json'] } })).toEqual([
      'site.paths.extraAllowedPaths[0]',
    ]);
  });

  it('flags a lowercase method', () => {
    expect(check({ methods: { blocked: ['trace'] } })).toEqual(['site.methods.blocked[0]']);
  });

  it('flags an empty user-agent substring, which would match everything', () => {
    expect(check({ userAgents: { extraBlocked: ['  '] } })).toEqual([
      'site.userAgents.extraBlocked[0]',
    ]);
  });
});

describe('challenge and headers', () => {
  it('flags an enabled challenge with no rules', () => {
    expect(check({ challenge: { enabled: true } })).toEqual(['site.challenge']);
  });

  it('flags hstsPreload without includeSubDomains', () => {
    expect(check({ headers: { hsts: true, hstsPreload: true } })).toEqual([
      'site.headers.hstsPreload',
    ]);
  });

  it('accepts a complete HSTS configuration', () => {
    expect(
      check({
        headers: { hsts: true, hstsPreload: true, hstsIncludeSubdomains: true },
      }),
    ).toEqual([]);
  });
});
