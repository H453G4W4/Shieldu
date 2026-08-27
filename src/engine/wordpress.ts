/**
 * WordPress-specific rules.
 *
 * Every rule here is behind a flag, because on a real WordPress install almost any of
 * these endpoints can be load-bearing. The "why" for each exemption is commented inline —
 * these are the rules that break sites when they are wrong.
 *
 * Rules that must NEVER fire (hard-coded exemptions, not flags):
 *   - /wp-admin/admin-ajax.php  : used by logged-out visitors too (forms, carts, search).
 *   - /wp-admin/admin-post.php  : same, for form handlers.
 * They are checked before every wp-admin rule below.
 */

import type { RequestContext } from '../context';
import type { Decision } from '../config/types';
import { ipInAnyCidr } from './ip';

/** Endpoints under /wp-admin/ that logged-out visitors legitimately hit. */
const WP_ADMIN_PUBLIC_ENDPOINTS: readonly string[] = [
  '/wp-admin/admin-ajax.php',
  '/wp-admin/admin-post.php',
];

/** Installer / setup scripts. Reachable only during a real install or migration. */
const WP_INSTALLER_PATHS: readonly string[] = [
  '/wp-admin/install.php',
  '/wp-admin/upgrade.php',
  '/wp-admin/setup-config.php',
  '/wp-admin/install-helper.php',
];

/** Files that ship with WordPress and leak version or configuration information. */
const WP_EXPOSED_FILES: readonly string[] = [
  '/wp-config.php',
  '/wp-config-sample.php',
  '/wp-config.php.txt',
  '/readme.html',
  '/license.txt',
  '/wp-content/debug.log',
  '/wp-content/uploads/debug.log',
];

/** Executable extensions that must never be served from the uploads directory. */
const PHP_EXTENSION_RE = /\.(?:php[0-9]?|phtml|phps|phar|inc)(?:$|[/?#])/i;

/** WordPress paths that, on a non-WordPress site, can only be scanner traffic. */
const WP_PROBE_PATHS: readonly string[] = [
  '/wp-login.php',
  '/xmlrpc.php',
  '/wp-config.php',
  '/wp-admin/',
  '/wp-includes/',
  '/wp-content/',
  '/wp-cron.php',
  '/wp-json/',
  '/wordpress/',
  '/wp/wp-admin/',
];

/**
 * Heuristic "is this visitor logged in?".
 *
 * WordPress sets a `wordpress_logged_in_<hash>` cookie for authenticated sessions. We
 * cannot validate it at the edge (that needs the site's AUTH salts), so this is a
 * CONVENIENCE HEURISTIC ONLY, never a security boundary. It is used exclusively to avoid
 * blocking real editors on endpoints that are otherwise noisy — an attacker who forges
 * the cookie gains nothing beyond skipping a couple of enumeration rules, and WordPress
 * itself still authenticates the request.
 */
export function looksLoggedIn(ctx: RequestContext): boolean {
  const cookie = ctx.request.headers.get('Cookie');
  if (cookie === null) return false;
  return cookie.indexOf('wordpress_logged_in_') !== -1;
}

function isPublicAdminEndpoint(path: string): boolean {
  for (let i = 0; i < WP_ADMIN_PUBLIC_ENDPOINTS.length; i++) {
    if (path === WP_ADMIN_PUBLIC_ENDPOINTS[i]) return true;
  }
  return false;
}

/** True when the client passes the login allow lists (IP and/or country). */
function passesLoginAllowlist(ctx: RequestContext): boolean {
  const site = ctx.site;
  const hasIpList = site.loginAllowIp.length > 0;
  const hasCountryList = site.loginAllowCountry.size > 0;
  if (!hasIpList && !hasCountryList) return true;

  // Either list may grant access. This is intentional: an admin who travels can be
  // covered by the country list while the office keeps a fixed-IP entry.
  if (hasIpList && ipInAnyCidr(ctx.ipBytes, site.loginAllowIp)) return true;
  if (hasCountryList && ctx.country !== '' && site.loginAllowCountry.has(ctx.country)) return true;
  return false;
}

/** Does the query string enumerate users via `?author=<numeric id>`? */
function isNumericAuthorQuery(url: URL): boolean {
  const author = url.searchParams.get('author');
  if (author === null || author.length === 0 || author.length > 9) return false;
  for (let i = 0; i < author.length; i++) {
    const code = author.charCodeAt(i);
    if (code < 48 || code > 57) return false;
  }
  return true;
}

/**
 * WordPress rule group. Runs only when `site.type === "wordpress"`.
 * Returns a `rateLimit` decision when the endpoint should be metered rather than blocked;
 * the pipeline resolves that against the binding.
 */
export function evaluateWordPress(ctx: RequestContext): Decision | null {
  const wp = ctx.site.config.wordpress;
  const path = ctx.pathDecoded;

  // ---- Hard exemptions, checked first so no rule below can ever reach them. ----
  if (isPublicAdminEndpoint(path)) return null;

  // ---- xmlrpc ----
  if (path === '/xmlrpc.php') {
    if (!wp.allowXmlrpc) {
      return { ruleId: 'wp.xmlrpc.blocked', action: 'block', status: 403 };
    }
    // Jetpack / WooCommerce / the WP mobile app need xmlrpc, but it is also the classic
    // brute-force amplifier (system.multicall). Allowed but metered.
    return { ruleId: 'wp.xmlrpc.rateLimit', action: 'rateLimit', status: 429, detail: 'xmlrpc' };
  }

  // ---- Installer files ----
  if (!wp.allowInstaller) {
    for (let i = 0; i < WP_INSTALLER_PATHS.length; i++) {
      if (path === WP_INSTALLER_PATHS[i]) {
        return { ruleId: 'wp.installer', action: 'block', status: 403, detail: path };
      }
    }
  }

  // ---- Files that leak version/config information ----
  for (let i = 0; i < WP_EXPOSED_FILES.length; i++) {
    if (path === WP_EXPOSED_FILES[i]) {
      return { ruleId: 'wp.exposedFile', action: 'block', status: 403, detail: path };
    }
  }

  // ---- Direct execution of anything under wp-includes ----
  // wp-includes/*.php is never meant to be requested directly; every historical RFI/LFI
  // chain in WordPress has gone through it.
  if (path.startsWith('/wp-includes/') && PHP_EXTENSION_RE.test(path)) {
    return { ruleId: 'wp.includesPhp', action: 'block', status: 403, detail: path };
  }

  // ---- PHP in the uploads directory ----
  // Uploads are user-controlled. A .php file there is either a shell or a misconfiguration.
  if (path.startsWith('/wp-content/uploads/') && PHP_EXTENSION_RE.test(path)) {
    return { ruleId: 'wp.uploadsPhp', action: 'block', status: 403, detail: path };
  }

  // ---- wp-cron ----
  if (path === '/wp-cron.php' && !wp.allowExternalCron) {
    // WordPress triggers wp-cron.php internally via a loopback request from the origin,
    // which never passes through Cloudflare, so blocking it at the edge is safe unless
    // the site uses an external cron service. Turn `allowExternalCron` on if it does.
    return { ruleId: 'wp.cron', action: 'block', status: 403 };
  }

  // ---- Login and admin ----
  if (path === '/wp-login.php' || path.startsWith('/wp-admin/') || path === '/wp-admin') {
    if (!passesLoginAllowlist(ctx)) {
      return { ruleId: 'wp.login.allowlist', action: 'block', status: 403, detail: ctx.country };
    }
    if (ctx.method === 'POST') {
      return { ruleId: 'wp.login.rateLimit', action: 'rateLimit', status: 429, detail: 'login' };
    }
    return null;
  }

  // ---- Comments ----
  if (path === '/wp-comments-post.php' && ctx.method === 'POST' && wp.rateLimitComments) {
    return {
      ruleId: 'wp.comments.rateLimit',
      action: 'rateLimit',
      status: 429,
      detail: 'comments',
    };
  }

  // ---- REST API ----
  const isRest = path === '/wp-json' || path.startsWith('/wp-json/');
  if (isRest) {
    if (wp.blockRestApiPublic && !looksLoggedIn(ctx)) {
      return { ruleId: 'wp.restApi.public', action: 'block', status: 403 };
    }
    if (
      wp.blockUserEnumeration &&
      (path.startsWith('/wp-json/wp/v2/users') || path.startsWith('/wp-json/wp/v2/user')) &&
      !looksLoggedIn(ctx)
    ) {
      // The users endpoint is the single easiest way to harvest valid usernames.
      // Logged-in editors legitimately need it (author pickers), hence the exemption.
      return { ruleId: 'wp.userEnum.rest', action: 'block', status: 403 };
    }
    return null;
  }

  // ---- User enumeration via ?author=<id> ----
  if (wp.blockUserEnumeration && isNumericAuthorQuery(ctx.url) && !looksLoggedIn(ctx)) {
    return { ruleId: 'wp.userEnum.query', action: 'block', status: 403 };
  }

  // ---- Author archives ----
  if (wp.blockAuthorArchives && (path === '/author' || path.startsWith('/author/'))) {
    return { ruleId: 'wp.authorArchive', action: 'block', status: 403, detail: path };
  }

  return null;
}

/**
 * WordPress probe detection for `type: "generic"` sites. A request for /wp-login.php on a
 * site that does not run WordPress is a scanner, full stop.
 */
export function evaluateWordPressProbes(ctx: RequestContext): Decision | null {
  if (!ctx.site.config.blockWordpressProbes) return null;
  const path = ctx.pathDecoded;
  for (let i = 0; i < WP_PROBE_PATHS.length; i++) {
    const probe = WP_PROBE_PATHS[i] as string;
    if (probe.endsWith('/') ? path.startsWith(probe) : path === probe) {
      return { ruleId: 'wp.probe', action: 'block', status: 403, detail: path };
    }
  }
  return null;
}
