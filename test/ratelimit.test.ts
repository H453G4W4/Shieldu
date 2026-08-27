import { describe, expect, it } from 'vitest';
import { applyRateLimit, rateLimitKey, resetRateLimitWarnings } from '../src/engine/ratelimit';
import { evaluate } from '../src/engine/pipeline';
import type { Env } from '../src/config/types';
import { makeContext, makeSite } from './helpers';

/** A limiter that allows the first `allowCount` calls, then refuses. */
function limiter(allowCount: number, seen: string[] = []) {
  let calls = 0;
  return {
    binding: {
      limit: ({ key }: { key: string }) => {
        seen.push(key);
        calls += 1;
        return Promise.resolve({ success: calls <= allowCount });
      },
    },
    seen,
  };
}

describe('rateLimitKey', () => {
  it('scopes the counter by group, host and IP', () => {
    expect(rateLimitKey('login', 'example.com', '203.0.113.5')).toBe(
      'login:example.com:203.0.113.5',
    );
  });

  it('uses a placeholder when the IP is unknown', () => {
    expect(rateLimitKey('login', 'example.com', '')).toBe('login:example.com:unknown');
  });
});

describe('applyRateLimit', () => {
  it('returns null while the limit is not exceeded', async () => {
    const site = makeSite();
    const ctx = makeContext(site, { ip: '203.0.113.5' });
    const { binding, seen } = limiter(1);
    const env = { RL_LOGIN: binding } as unknown as Env;

    expect(await applyRateLimit(ctx, env, 'login', 'wp.login.rateLimit')).toBeNull();
    expect(seen).toEqual(['login:example.com:203.0.113.5']);
  });

  it('returns a 429 with Retry-After once the limit is exceeded', async () => {
    const site = makeSite();
    const ctx = makeContext(site, { ip: '203.0.113.5' });
    const { binding } = limiter(0);
    const env = { RL_LOGIN: binding } as unknown as Env;

    const decision = await applyRateLimit(ctx, env, 'login', 'wp.login.rateLimit');
    expect(decision?.status).toBe(429);
    expect(decision?.ruleId).toBe('wp.login.rateLimit');
    expect(decision?.retryAfterSeconds).toBe(60);
    expect(decision?.detail).toBe('login:5/60s');
  });

  it('honours an explicit retryAfterSeconds', async () => {
    const site = makeSite({ rateLimits: { login: { limit: 5, period: 60, retryAfterSeconds: 15 } } });
    const ctx = makeContext(site, { ip: '203.0.113.5' });
    const env = { RL_LOGIN: limiter(0).binding } as unknown as Env;

    const decision = await applyRateLimit(ctx, env, 'login', 'wp.login.rateLimit');
    expect(decision?.retryAfterSeconds).toBe(15);
  });

  it('does nothing when the group is disabled for the site', async () => {
    const site = makeSite({ rateLimits: { login: null } });
    const ctx = makeContext(site, { ip: '203.0.113.5' });
    const { binding, seen } = limiter(0);
    const env = { RL_LOGIN: binding } as unknown as Env;

    expect(await applyRateLimit(ctx, env, 'login', 'wp.login.rateLimit')).toBeNull();
    expect(seen).toEqual([]);
  });

  it('fails open when the binding is missing', async () => {
    resetRateLimitWarnings();
    const site = makeSite();
    const ctx = makeContext(site, { ip: '203.0.113.5' });
    expect(await applyRateLimit(ctx, {}, 'login', 'wp.login.rateLimit')).toBeNull();
  });

  it('fails open when the binding throws', async () => {
    const site = makeSite();
    const ctx = makeContext(site, { ip: '203.0.113.5' });
    const env = {
      RL_LOGIN: { limit: () => Promise.reject(new Error('limiter down')) },
    } as unknown as Env;
    expect(await applyRateLimit(ctx, env, 'login', 'wp.login.rateLimit')).toBeNull();
  });
});

describe('rate limits inside the pipeline', () => {
  it('meters POST wp-login.php via the login group', async () => {
    const site = makeSite({ type: 'wordpress' });
    const { binding, seen } = limiter(0);
    const env = { RL_LOGIN: binding } as unknown as Env;

    const decision = await evaluate(
      makeContext(site, {
        ip: '203.0.113.5',
        url: 'https://example.com/wp-login.php',
        method: 'POST',
      }),
      env,
    );
    expect(decision.status).toBe(429);
    expect(decision.ruleId).toBe('wp.login.rateLimit');
    expect(seen[0]).toBe('login:example.com:203.0.113.5');
  });

  it('does not meter a GET of wp-login.php', async () => {
    const site = makeSite({ type: 'wordpress' });
    const { binding, seen } = limiter(0);
    const env = { RL_LOGIN: binding } as unknown as Env;

    const decision = await evaluate(
      makeContext(site, { ip: '203.0.113.5', url: 'https://example.com/wp-login.php' }),
      env,
    );
    expect(decision.action).toBe('allow');
    expect(seen).toEqual([]);
  });

  it('meters xmlrpc.php when it is allowed', async () => {
    const site = makeSite({ type: 'wordpress', wordpress: { allowXmlrpc: true } });
    const env = { RL_XMLRPC: limiter(0).binding } as unknown as Env;

    const decision = await evaluate(
      makeContext(site, { ip: '203.0.113.5', url: 'https://example.com/xmlrpc.php' }),
      env,
    );
    expect(decision.ruleId).toBe('wp.xmlrpc.rateLimit');
    expect(decision.status).toBe(429);
  });

  it('meters POST wp-comments-post.php', async () => {
    const site = makeSite({ type: 'wordpress' });
    const env = { RL_COMMENTS: limiter(0).binding } as unknown as Env;

    const decision = await evaluate(
      makeContext(site, {
        ip: '203.0.113.5',
        url: 'https://example.com/wp-comments-post.php',
        method: 'POST',
      }),
      env,
    );
    expect(decision.ruleId).toBe('wp.comments.rateLimit');
  });

  it('applies the general limit only when it is configured', async () => {
    const off = makeSite();
    const { binding, seen } = limiter(0);
    await evaluate(makeContext(off, { ip: '203.0.113.5' }), {
      RL_GENERAL: binding,
    } as unknown as Env);
    expect(seen).toEqual([]);

    const on = makeSite({ rateLimits: { general: { limit: 100, period: 60 } } });
    const decision = await evaluate(makeContext(on, { ip: '203.0.113.5' }), {
      RL_GENERAL: limiter(0).binding,
    } as unknown as Env);
    expect(decision.ruleId).toBe('rateLimit.general');
    expect(decision.status).toBe(429);
  });

  it('is skipped entirely for an allow-listed client', async () => {
    const site = makeSite({
      allow: { ip: ['203.0.113.5'] },
      rateLimits: { general: { limit: 1, period: 60 } },
    });
    const { binding, seen } = limiter(0);
    const decision = await evaluate(makeContext(site, { ip: '203.0.113.5' }), {
      RL_GENERAL: binding,
    } as unknown as Env);
    expect(decision.action).toBe('allow');
    expect(seen).toEqual([]);
  });
});
