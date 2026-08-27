import { describe, expect, it } from 'vitest';
import { evaluate } from '../src/engine/pipeline';
import { emptyEnv, makeContext, makeSite } from './helpers';

describe('pipeline ordering', () => {
  it('allows an ordinary request', async () => {
    const site = makeSite({ hosts: ['example.com'] });
    const decision = await evaluate(makeContext(site, { ip: '203.0.113.5' }), emptyEnv);
    expect(decision.action).toBe('allow');
    expect(decision.ruleId).toBe('default.allow');
  });

  it('blocks a listed IP', async () => {
    const site = makeSite({ block: { ip: ['203.0.113.0/24'] } });
    const decision = await evaluate(makeContext(site, { ip: '203.0.113.5' }), emptyEnv);
    expect(decision.action).toBe('block');
    expect(decision.ruleId).toBe('list.block.ip');
    expect(decision.status).toBe(403);
  });

  it('blocks a listed ASN', async () => {
    const site = makeSite({ block: { asn: [64500] } });
    const decision = await evaluate(makeContext(site, { ip: '203.0.113.5' }), emptyEnv);
    expect(decision.ruleId).toBe('list.block.asn');
    expect(decision.detail).toBe('AS64500');
  });

  it('blocks a listed country in block mode', async () => {
    const site = makeSite({ block: { country: ['RU'] }, countryMode: 'block' });
    const decision = await evaluate(
      makeContext(site, { ip: '203.0.113.5', country: 'RU' }),
      emptyEnv,
    );
    expect(decision.ruleId).toBe('list.block.country');
    expect(decision.detail).toBe('RU');
  });

  it('ignores the country block list when countryMode is allow', async () => {
    const site = makeSite({
      block: { country: ['RU'] },
      allow: { country: ['RU'] },
      countryMode: 'allow',
    });
    const decision = await evaluate(
      makeContext(site, { ip: '203.0.113.5', country: 'RU' }),
      emptyEnv,
    );
    expect(decision.action).toBe('allow');
  });

  it('blocks every country outside the allow list in allow mode', async () => {
    const site = makeSite({ allow: { country: ['MA', 'FR'] }, countryMode: 'allow' });
    const blocked = await evaluate(
      makeContext(site, { ip: '203.0.113.5', country: 'DE' }),
      emptyEnv,
    );
    expect(blocked.ruleId).toBe('list.allowMode.country');
    expect(blocked.detail).toBe('DE');

    const allowed = await evaluate(
      makeContext(site, { ip: '203.0.113.5', country: 'MA' }),
      emptyEnv,
    );
    expect(allowed.action).toBe('allow');
  });

  it('blocks an unknown country in allow mode', async () => {
    const site = makeSite({ allow: { country: ['MA'] }, countryMode: 'allow' });
    const decision = await evaluate(
      makeContext(site, { ip: '203.0.113.5', noCf: true }),
      emptyEnv,
    );
    expect(decision.ruleId).toBe('list.allowMode.country');
    expect(decision.detail).toBe('unknown');
  });
});

describe('allow list precedence', () => {
  type Overrides = NonNullable<Parameters<typeof makeSite>[0]>;
  const cases: Array<[string, Overrides]> = [
    ['ip block list', { block: { ip: ['203.0.113.0/24'] } }],
    ['asn block list', { block: { asn: [64500] } }],
    ['country block list', { block: { country: ['US'] } }],
    ['method rules', { methods: { blocked: ['GET'] } }],
    ['scanner paths', {}],
    ['user agent rules', { userAgents: { extraBlocked: ['sqlmap'] } }],
    ['wordpress rules', { type: 'wordpress' }],
  ];

  for (const [name, overrides] of cases) {
    it(`wins over ${name}`, async () => {
      const site = makeSite({
        ...overrides,
        allow: { ...(overrides.allow ?? {}), ip: ['203.0.113.5'] },
      });
      const decision = await evaluate(
        makeContext(site, {
          ip: '203.0.113.5',
          url: 'https://example.com/.git/config',
          ua: 'sqlmap/1.7',
        }),
        emptyEnv,
      );
      expect(decision.action, name).toBe('allow');
      expect(decision.ruleId, name).toBe('list.allow.ip');
    });
  }

  it('also honours an ASN allow entry', async () => {
    const site = makeSite({ allow: { asn: [64500] }, block: { ip: ['203.0.113.0/24'] } });
    const decision = await evaluate(makeContext(site, { ip: '203.0.113.5' }), emptyEnv);
    expect(decision.ruleId).toBe('list.allow.asn');
  });

  it('also honours a country allow entry', async () => {
    const site = makeSite({ allow: { country: ['US'] }, block: { ip: ['203.0.113.0/24'] } });
    const decision = await evaluate(makeContext(site, { ip: '203.0.113.5' }), emptyEnv);
    expect(decision.ruleId).toBe('list.allow.country');
  });
});

describe('missing request.cf', () => {
  it('does not crash and does not match geo rules', async () => {
    const site = makeSite({ block: { country: ['US'], asn: [64500] } });
    const decision = await evaluate(
      makeContext(site, { ip: '203.0.113.5', noCf: true }),
      emptyEnv,
    );
    expect(decision.action).toBe('allow');
  });

  it('does not crash when CF-Connecting-IP is missing', async () => {
    const site = makeSite({ block: { ip: ['203.0.113.0/24'] } });
    const decision = await evaluate(makeContext(site, {}), emptyEnv);
    expect(decision.action).toBe('allow');
  });
});

describe('extraAllowedPaths', () => {
  it('skips the path, wordpress and user-agent groups', async () => {
    const site = makeSite({
      type: 'wordpress',
      paths: { extraAllowedPaths: ['/xmlrpc.php'] },
      userAgents: { extraBlocked: ['sqlmap'] },
    });
    const decision = await evaluate(
      makeContext(site, { ip: '203.0.113.5', url: 'https://example.com/xmlrpc.php', ua: 'sqlmap' }),
      emptyEnv,
    );
    expect(decision.action).toBe('allow');
  });

  it('does not skip the block lists', async () => {
    const site = makeSite({
      paths: { extraAllowedPaths: ['/.git/config'] },
      block: { ip: ['203.0.113.5'] },
    });
    const decision = await evaluate(
      makeContext(site, { ip: '203.0.113.5', url: 'https://example.com/.git/config' }),
      emptyEnv,
    );
    expect(decision.ruleId).toBe('list.block.ip');
  });
});
