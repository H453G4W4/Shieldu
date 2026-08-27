import { describe, expect, it } from 'vitest';
import { hasClearance, issueClearance, verifyClearance } from '../src/actions/challenge';
import { evaluate } from '../src/engine/pipeline';
import type { Env } from '../src/config/types';
import { makeContext, makeSite } from './helpers';

const SECRET = 'test-cookie-secret';
const NOW = 1_800_000_000_000;

const challengeEnv = {
  SHIELD_COOKIE_SECRET: SECRET,
  TURNSTILE_SITE_KEY: '1x00000000000000000000AA',
} as Env;

function challengeSite(rules: string[]) {
  return makeSite({
    type: 'wordpress',
    challenge: { enabled: true, challengeRules: rules, ttlSeconds: 3600 },
  });
}

describe('clearance cookie', () => {
  it('round-trips a signed clearance', async () => {
    const value = await issueClearance(SECRET, '203.0.113.5', 3600, NOW);
    expect(await verifyClearance(SECRET, '203.0.113.5', value, NOW)).toBe(true);
  });

  it('rejects a clearance issued for another IP', async () => {
    const value = await issueClearance(SECRET, '203.0.113.5', 3600, NOW);
    expect(await verifyClearance(SECRET, '198.51.100.9', value, NOW)).toBe(false);
  });

  it('rejects a clearance signed with another secret', async () => {
    const value = await issueClearance('other-secret', '203.0.113.5', 3600, NOW);
    expect(await verifyClearance(SECRET, '203.0.113.5', value, NOW)).toBe(false);
  });

  it('rejects an expired clearance', async () => {
    const value = await issueClearance(SECRET, '203.0.113.5', 60, NOW);
    expect(await verifyClearance(SECRET, '203.0.113.5', value, NOW + 61_000)).toBe(false);
  });

  it('rejects a tampered expiry', async () => {
    const value = await issueClearance(SECRET, '203.0.113.5', 60, NOW);
    const signature = value.slice(value.indexOf('.') + 1);
    const forged = `${Math.floor(NOW / 1000) + 99999}.${signature}`;
    expect(await verifyClearance(SECRET, '203.0.113.5', forged, NOW)).toBe(false);
  });

  it('rejects malformed values without throwing', async () => {
    for (const value of ['', '.', 'abc', '.sig', '123', '123.', 'x.y', 'a'.repeat(500)]) {
      expect(await verifyClearance(SECRET, '203.0.113.5', value, NOW), value).toBe(false);
    }
  });
});

describe('hasClearance', () => {
  it('is false when the challenge action is disabled', async () => {
    const site = makeSite();
    const value = await issueClearance(SECRET, '203.0.113.5', 3600, NOW);
    const ctx = makeContext(site, {
      ip: '203.0.113.5',
      cookie: `shield_clearance=${value}`,
    });
    expect(await hasClearance(ctx, challengeEnv, NOW)).toBe(false);
  });

  it('is false when the cookie secret is not configured', async () => {
    const site = challengeSite(['wp.']);
    const value = await issueClearance(SECRET, '203.0.113.5', 3600, NOW);
    const ctx = makeContext(site, {
      ip: '203.0.113.5',
      cookie: `shield_clearance=${value}`,
    });
    expect(await hasClearance(ctx, {}, NOW)).toBe(false);
  });

  it('picks the cookie out of a multi-cookie header', async () => {
    const site = challengeSite(['wp.']);
    const value = await issueClearance(SECRET, '203.0.113.5', 3600, NOW);
    const ctx = makeContext(site, {
      ip: '203.0.113.5',
      cookie: `wordpress_test_cookie=1; shield_clearance=${value}; other=2`,
    });
    expect(await hasClearance(ctx, challengeEnv, NOW)).toBe(true);
  });
});

describe('challenge escalation in the pipeline', () => {
  it('turns a listed rule into a challenge instead of a block', async () => {
    const site = challengeSite(['wp.xmlrpc']);
    const decision = await evaluate(
      makeContext(site, { ip: '203.0.113.5', url: 'https://example.com/xmlrpc.php' }),
      challengeEnv,
    );
    expect(decision.action).toBe('challenge');
    expect(decision.ruleId).toBe('wp.xmlrpc.blocked');
  });

  it('leaves an unlisted rule blocking outright', async () => {
    const site = challengeSite(['ua.']);
    const decision = await evaluate(
      makeContext(site, { ip: '203.0.113.5', url: 'https://example.com/xmlrpc.php' }),
      challengeEnv,
    );
    expect(decision.action).toBe('block');
  });

  it('does nothing when the challenge action is disabled', async () => {
    const site = makeSite({ type: 'wordpress', challenge: { challengeRules: ['wp.'] } });
    const decision = await evaluate(
      makeContext(site, { ip: '203.0.113.5', url: 'https://example.com/xmlrpc.php' }),
      challengeEnv,
    );
    expect(decision.action).toBe('block');
  });

  it('lets a visitor with a valid clearance straight through', async () => {
    const site = challengeSite(['wp.xmlrpc']);
    const value = await issueClearance(SECRET, '203.0.113.5', 3600, Date.now());
    const decision = await evaluate(
      makeContext(site, {
        ip: '203.0.113.5',
        url: 'https://example.com/xmlrpc.php',
        cookie: `shield_clearance=${value}`,
      }),
      challengeEnv,
    );
    expect(decision.action).toBe('allow');
    expect(decision.ruleId).toBe('challenge.cleared');
    expect(decision.detail).toBe('wp.xmlrpc.blocked');
  });

  it('never escalates an allow decision', async () => {
    const site = challengeSite(['default.', 'list.']);
    const decision = await evaluate(makeContext(site, { ip: '203.0.113.5' }), challengeEnv);
    expect(decision.action).toBe('allow');
  });
});
