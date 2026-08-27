import { describe, expect, it } from 'vitest';
import { evaluate } from '../src/engine/pipeline';
import { emptyEnv, makeContext, makeSite } from './helpers';
import type { DeepPartial, SiteConfig } from '../src/config/types';

const LOGGED_IN_COOKIE = 'wordpress_logged_in_0123456789abcdef=admin%7C1700000000%7Cabc; path=/';

function wpSite(overrides: DeepPartial<SiteConfig> = {}) {
  return makeSite({ type: 'wordpress', hosts: ['example.com'], ...overrides });
}

async function decide(
  site: ReturnType<typeof makeSite>,
  options: Parameters<typeof makeContext>[1],
) {
  return evaluate(makeContext(site, { ip: '203.0.113.5', ...options }), emptyEnv);
}

describe('WordPress rules -- must not break the site', () => {
  it('always allows admin-ajax.php, even for logged-out visitors', async () => {
    const site = wpSite({ wordpress: { loginAllowlistIp: ['198.51.100.1'] } });
    const decision = await decide(site, {
      url: 'https://example.com/wp-admin/admin-ajax.php?action=my_form',
      method: 'POST',
    });
    expect(decision.action).toBe('allow');
  });

  it('always allows admin-post.php', async () => {
    const site = wpSite({ wordpress: { loginAllowlistIp: ['198.51.100.1'] } });
    const decision = await decide(site, {
      url: 'https://example.com/wp-admin/admin-post.php',
      method: 'POST',
    });
    expect(decision.action).toBe('allow');
  });

  it('allows /wp-json/ by default', async () => {
    const decision = await decide(wpSite(), { url: 'https://example.com/wp-json/wp/v2/posts' });
    expect(decision.action).toBe('allow');
  });

  it('allows a logged-in request to /wp-json/wp/v2/users', async () => {
    const decision = await decide(wpSite(), {
      url: 'https://example.com/wp-json/wp/v2/users',
      cookie: LOGGED_IN_COOKIE,
    });
    expect(decision.action).toBe('allow');
  });

  it('allows /author/<slug>/ by default', async () => {
    const decision = await decide(wpSite(), { url: 'https://example.com/author/jane/' });
    expect(decision.action).toBe('allow');
  });

  it('allows wp-cron.php when external cron is enabled', async () => {
    const site = wpSite({ wordpress: { allowExternalCron: true } });
    const decision = await decide(site, { url: 'https://example.com/wp-cron.php?doing_wp_cron' });
    expect(decision.action).toBe('allow');
  });

  it('allows an ordinary upload', async () => {
    const decision = await decide(wpSite(), {
      url: 'https://example.com/wp-content/uploads/2026/01/photo.jpg',
    });
    expect(decision.action).toBe('allow');
  });

  it('allows a zip deep inside uploads (only root-level backups are blocked)', async () => {
    const decision = await decide(wpSite(), {
      url: 'https://example.com/wp-content/uploads/2026/01/gallery.zip',
    });
    expect(decision.action).toBe('allow');
  });

  it('allows a plugin asset under wp-content', async () => {
    const decision = await decide(wpSite(), {
      url: 'https://example.com/wp-content/plugins/acme/assets/app.js?ver=1.2',
    });
    expect(decision.action).toBe('allow');
  });

  it('allows a GET of wp-login.php when there is no allow list', async () => {
    const decision = await decide(wpSite(), { url: 'https://example.com/wp-login.php' });
    expect(decision.action).toBe('allow');
  });
});

describe('WordPress rules -- blocking', () => {
  it('blocks xmlrpc.php by default', async () => {
    const decision = await decide(wpSite(), { url: 'https://example.com/xmlrpc.php' });
    expect(decision.ruleId).toBe('wp.xmlrpc.blocked');
    expect(decision.status).toBe(403);
  });

  it('rate-limits xmlrpc.php instead when allowXmlrpc is on', async () => {
    const site = wpSite({ wordpress: { allowXmlrpc: true } });
    // Without a binding the limiter fails open, so the request is allowed through.
    const decision = await decide(site, { url: 'https://example.com/xmlrpc.php', method: 'POST' });
    expect(decision.action).toBe('allow');
  });

  it('blocks the installer scripts', async () => {
    for (const path of [
      '/wp-admin/install.php',
      '/wp-admin/upgrade.php',
      '/wp-admin/setup-config.php',
    ]) {
      const decision = await decide(wpSite(), { url: `https://example.com${path}` });
      expect(decision.ruleId, path).toBe('wp.installer');
    }
  });

  it('allows the installer scripts when allowInstaller is on', async () => {
    const site = wpSite({ wordpress: { allowInstaller: true } });
    const decision = await decide(site, { url: 'https://example.com/wp-admin/install.php' });
    expect(decision.action).toBe('allow');
  });

  it('blocks files that leak version or configuration information', async () => {
    for (const path of [
      '/wp-config.php',
      '/wp-config-sample.php',
      '/readme.html',
      '/license.txt',
      '/wp-content/debug.log',
    ]) {
      const decision = await decide(wpSite(), { url: `https://example.com${path}` });
      expect(['wp.exposedFile', 'path.sensitiveFile'], path).toContain(decision.ruleId);
      expect(decision.status, path).toBe(403);
    }
  });

  it('blocks direct execution of wp-includes php files', async () => {
    const decision = await decide(wpSite(), {
      url: 'https://example.com/wp-includes/wlwmanifest.xml.php',
    });
    expect(decision.ruleId).toBe('wp.includesPhp');
  });

  it('blocks php in the uploads directory, including odd extensions', async () => {
    for (const path of [
      '/wp-content/uploads/2026/01/shell.php',
      '/wp-content/uploads/shell.php5',
      '/wp-content/uploads/shell.phtml',
      '/wp-content/uploads/shell.phar',
      '/wp-content/uploads/shell.php?x=1',
    ]) {
      const decision = await decide(wpSite(), { url: `https://example.com${path}` });
      expect(decision.ruleId, path).toBe('wp.uploadsPhp');
    }
  });

  it('blocks wp-cron.php from outside by default', async () => {
    const decision = await decide(wpSite(), { url: 'https://example.com/wp-cron.php' });
    expect(decision.ruleId).toBe('wp.cron');
  });

  it('blocks user enumeration via a numeric author query', async () => {
    const decision = await decide(wpSite(), { url: 'https://example.com/?author=1' });
    expect(decision.ruleId).toBe('wp.userEnum.query');
  });

  it('does not treat a non-numeric author query as enumeration', async () => {
    const decision = await decide(wpSite(), { url: 'https://example.com/?author=jane' });
    expect(decision.action).toBe('allow');
  });

  it('blocks unauthenticated /wp-json/wp/v2/users', async () => {
    const decision = await decide(wpSite(), {
      url: 'https://example.com/wp-json/wp/v2/users?per_page=100',
    });
    expect(decision.ruleId).toBe('wp.userEnum.rest');
  });

  it('honours blockAuthorArchives when enabled', async () => {
    const site = wpSite({ wordpress: { blockAuthorArchives: true } });
    const decision = await decide(site, { url: 'https://example.com/author/jane/' });
    expect(decision.ruleId).toBe('wp.authorArchive');
  });

  it('honours blockRestApiPublic when enabled, but not for logged-in users', async () => {
    const site = wpSite({ wordpress: { blockRestApiPublic: true } });
    const blocked = await decide(site, { url: 'https://example.com/wp-json/wp/v2/posts' });
    expect(blocked.ruleId).toBe('wp.restApi.public');

    const allowed = await decide(site, {
      url: 'https://example.com/wp-json/wp/v2/posts',
      cookie: LOGGED_IN_COOKIE,
    });
    expect(allowed.action).toBe('allow');
  });
});

describe('WordPress login allow lists', () => {
  it('blocks wp-login.php from outside the IP allow list', async () => {
    const site = wpSite({ wordpress: { loginAllowlistIp: ['198.51.100.0/24'] } });
    const decision = await decide(site, { url: 'https://example.com/wp-login.php' });
    expect(decision.ruleId).toBe('wp.login.allowlist');
  });

  it('allows wp-login.php from inside the IP allow list', async () => {
    const site = wpSite({ wordpress: { loginAllowlistIp: ['203.0.113.0/24'] } });
    const decision = await decide(site, { url: 'https://example.com/wp-login.php' });
    expect(decision.action).toBe('allow');
  });

  it('allows access via the country allow list when the IP does not match', async () => {
    const site = wpSite({
      wordpress: { loginAllowlistIp: ['198.51.100.0/24'], loginAllowlistCountry: ['MA'] },
    });
    const decision = await decide(site, { url: 'https://example.com/wp-login.php', country: 'MA' });
    expect(decision.action).toBe('allow');
  });

  it('applies the allow list to /wp-admin/ too', async () => {
    const site = wpSite({ wordpress: { loginAllowlistIp: ['198.51.100.0/24'] } });
    const decision = await decide(site, { url: 'https://example.com/wp-admin/edit.php' });
    expect(decision.ruleId).toBe('wp.login.allowlist');
  });

  it('never applies the allow list to admin-ajax.php', async () => {
    const site = wpSite({ wordpress: { loginAllowlistIp: ['198.51.100.0/24'] } });
    const decision = await decide(site, {
      url: 'https://example.com/wp-admin/admin-ajax.php',
      method: 'POST',
    });
    expect(decision.action).toBe('allow');
  });
});

describe('WordPress probes on a generic site', () => {
  it('blocks wp paths on a non-WordPress site', async () => {
    const site = makeSite({ type: 'generic', blockWordpressProbes: true });
    for (const path of ['/wp-login.php', '/xmlrpc.php', '/wp-admin/', '/wp-content/uploads/a.png']) {
      const decision = await decide(site, { url: `https://example.com${path}` });
      expect(decision.ruleId, path).toBe('wp.probe');
    }
  });

  it('can be turned off', async () => {
    const site = makeSite({ type: 'generic', blockWordpressProbes: false });
    const decision = await decide(site, { url: 'https://example.com/wp-login.php' });
    expect(decision.action).toBe('allow');
  });

  it('does not apply the WordPress rule group to a generic site', async () => {
    const site = makeSite({ type: 'generic', blockWordpressProbes: false });
    const decision = await decide(site, { url: 'https://example.com/?author=1' });
    expect(decision.action).toBe('allow');
  });
});
