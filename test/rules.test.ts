import { describe, expect, it } from 'vitest';
import { evaluate } from '../src/engine/pipeline';
import { emptyEnv, makeContext, makeSite } from './helpers';

async function decide(
  site: ReturnType<typeof makeSite>,
  options: Parameters<typeof makeContext>[1] = {},
) {
  return evaluate(makeContext(site, { ip: '203.0.113.5', ...options }), emptyEnv);
}

describe('method rules', () => {
  it('blocks TRACE by default', async () => {
    const decision = await decide(makeSite(), { method: 'TRACE' });
    expect(decision.ruleId).toBe('method.blocked');
    expect(decision.status).toBe(405);
    expect(decision.detail).toBe('TRACE');
  });

  // TRACK and CONNECT cannot be constructed as a `Request` -- the Workers runtime rejects
  // them before a Worker ever sees them. They stay in the default block list as defence in
  // depth, so this asserts the matching logic rather than the runtime behaviour.
  it('matches any configured blocked method', async () => {
    const site = makeSite({ methods: { blocked: ['DELETE'] } });
    const decision = await decide(site, { method: 'DELETE' });
    expect(decision.ruleId).toBe('method.blocked');
    expect(decision.detail).toBe('DELETE');
  });

  it('allows the ordinary methods', async () => {
    const site = makeSite();
    for (const method of ['GET', 'POST', 'HEAD', 'PUT', 'DELETE', 'OPTIONS', 'PATCH']) {
      expect((await decide(site, { method })).action, method).toBe('allow');
    }
  });

  it('enforces an explicit allowed-methods list', async () => {
    const site = makeSite({ methods: { allowed: ['GET', 'HEAD'] } });
    expect((await decide(site, { method: 'GET' })).action).toBe('allow');
    const blocked = await decide(site, { method: 'POST' });
    expect(blocked.ruleId).toBe('method.notAllowed');
    expect(blocked.detail).toBe('POST');
  });
});

describe('sensitive path and scanner rules', () => {
  it('blocks the built-in sensitive paths', async () => {
    const site = makeSite();
    for (const path of [
      '/.env',
      '/.git/config',
      '/.svn/entries',
      '/.htaccess',
      '/.htpasswd',
      '/.aws/credentials',
      '/phpmyadmin/index.php',
      '/adminer.php',
      '/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php',
      '/cgi-bin/test.sh',
      '/server-status',
      '/wp-config.php.bak',
    ]) {
      const decision = await decide(site, { url: `https://example.com${path}` });
      expect(decision.action, path).toBe('block');
      expect(decision.ruleId, path).toMatch(/^path\./);
    }
  });

  it('catches a percent-encoded sensitive path', async () => {
    const site = makeSite();
    const decision = await decide(site, { url: 'https://example.com/%2egit/config' });
    expect(decision.ruleId).toBe('path.scanner');
  });

  it('blocks backup archives at the web root only', async () => {
    const site = makeSite();
    const blocked = await decide(site, { url: 'https://example.com/backup.sql' });
    expect(blocked.ruleId).toBe('path.backupFile');

    const allowed = await decide(site, { url: 'https://example.com/downloads/release.zip' });
    expect(allowed.action).toBe('allow');
  });

  it('honours extraBlockedPrefixes', async () => {
    const site = makeSite({ paths: { extraBlockedPrefixes: ['/internal/'] } });
    const decision = await decide(site, { url: 'https://example.com/internal/metrics' });
    expect(decision.ruleId).toBe('path.extraBlocked');
  });

  it('can be turned off entirely', async () => {
    const site = makeSite({ paths: { blockScannerPaths: false } });
    expect((await decide(site, { url: 'https://example.com/.env' })).action).toBe('allow');
  });

  it('does not block ordinary content paths', async () => {
    const site = makeSite();
    for (const path of [
      '/',
      '/blog/hello-world/',
      '/assets/main.css?v=3',
      '/.well-known/acme-challenge/token',
      '/robots.txt',
      '/sitemap.xml',
      '/feed/',
    ]) {
      expect((await decide(site, { url: `https://example.com${path}` })).action, path).toBe('allow');
    }
  });
});

describe('request anomaly checks', () => {
  it('blocks an over-long path', async () => {
    const site = makeSite({ paths: { maxPathLength: 64 } });
    const decision = await decide(site, { url: `https://example.com/${'a'.repeat(200)}` });
    expect(decision.ruleId).toBe('anomaly.pathTooLong');
    expect(decision.status).toBe(414);
  });

  it('blocks an over-long query string', async () => {
    const site = makeSite({ paths: { maxQueryLength: 32 } });
    const decision = await decide(site, { url: `https://example.com/?q=${'a'.repeat(200)}` });
    expect(decision.ruleId).toBe('anomaly.queryTooLong');
  });

  it('blocks an encoded null byte', async () => {
    const site = makeSite();
    const decision = await decide(site, { url: 'https://example.com/file%00.jpg' });
    expect(decision.ruleId).toBe('anomaly.nullByte');
    expect(decision.status).toBe(400);
  });

  it('blocks path traversal', async () => {
    const site = makeSite();
    const decision = await decide(site, { url: 'https://example.com/x/%2e%2e%2fetc/passwd' });
    expect(decision.ruleId).toBe('anomaly.traversal');
  });

  it('blocks obvious SQL injection in the query string', async () => {
    const site = makeSite();
    for (const query of ['?id=1+UNION+SELECT+password+FROM+users', '?id=1%20union%20all%20select']) {
      const decision = await decide(site, { url: `https://example.com/page${query}` });
      expect(decision.ruleId, query).toBe('anomaly.sqlPattern');
    }
  });

  it('blocks obvious XSS in the query string', async () => {
    const site = makeSite();
    const decision = await decide(site, { url: 'https://example.com/s?q=%3Cscript%3Ealert(1)' });
    expect(decision.ruleId).toBe('anomaly.xssPattern');
  });

  it('does not fire on ordinary queries', async () => {
    const site = makeSite();
    for (const query of [
      '?s=how+to+select+a+theme',
      '?utm_source=newsletter&utm_campaign=spring',
      '?page=2&order=desc',
      '?redirect_to=https%3A%2F%2Fexample.com%2Fwp-admin%2F',
    ]) {
      expect((await decide(site, { url: `https://example.com/${query}` })).action, query).toBe(
        'allow',
      );
    }
  });

  it('can be turned off', async () => {
    const site = makeSite({ paths: { anomalyChecks: false } });
    expect((await decide(site, { url: 'https://example.com/file%00.jpg' })).action).toBe('allow');
  });
});

describe('user-agent rules', () => {
  it('blocks known scanners', async () => {
    const site = makeSite();
    for (const ua of ['sqlmap/1.7.2#stable', 'Mozilla/5.0 (Nikto/2.5.0)', 'WPScan v3.8.22']) {
      const decision = await decide(site, { ua });
      expect(decision.ruleId, ua).toBe('ua.scanner');
    }
  });

  it('never blocks well-known crawlers, even with scanner rules on', async () => {
    const site = makeSite({ userAgents: { blockEmpty: true, blockGenericClients: true } });
    for (const ua of [
      'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
      'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)',
      'facebookexternalhit/1.1',
      'Mozilla/5.0 (compatible; YandexBot/3.0)',
    ]) {
      expect((await decide(site, { ua })).action, ua).toBe('allow');
    }
  });

  it('leaves an empty user agent alone by default', async () => {
    expect((await decide(makeSite(), { ua: '' })).action).toBe('allow');
    expect((await decide(makeSite(), {})).action).toBe('allow');
  });

  it('blocks an empty user agent when asked to', async () => {
    const site = makeSite({ userAgents: { blockEmpty: true } });
    expect((await decide(site, { ua: '' })).ruleId).toBe('ua.empty');
    expect((await decide(site, {})).ruleId).toBe('ua.empty');
  });

  it('leaves generic HTTP clients alone by default', async () => {
    expect((await decide(makeSite(), { ua: 'curl/8.4.0' })).action).toBe('allow');
    expect((await decide(makeSite(), { ua: 'python-requests/2.31.0' })).action).toBe('allow');
  });

  it('blocks generic HTTP clients when asked to', async () => {
    const site = makeSite({ userAgents: { blockGenericClients: true } });
    const decision = await decide(site, { ua: 'python-requests/2.31.0' });
    expect(decision.ruleId).toBe('ua.genericClient');
  });

  it('honours the extra block list, case insensitively', async () => {
    const site = makeSite({ userAgents: { extraBlocked: ['BadCrawler'] } });
    const decision = await decide(site, { ua: 'Mozilla/5.0 badcrawler/1.0' });
    expect(decision.ruleId).toBe('ua.extraBlocked');
  });

  it('allows an ordinary browser user agent', async () => {
    const ua =
      'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0 Safari/537.36';
    expect((await decide(makeSite(), { ua })).action).toBe('allow');
  });
});
