/**
 * Generic sensitive-path, scanner-path and request-anomaly rules.
 *
 * The lists below are the single place to extend generic path blocking. They are matched
 * against the lowercased, percent-decoded pathname so that `/.%67it/config` is caught the
 * same as `/.git/config`.
 *
 * Scope note: these checks are cheap heuristics for obvious scanner noise. Real payload
 * inspection belongs in Cloudflare's managed WAF, which runs before Workers and costs
 * nothing on the Free plan. See docs/cloudflare-setup.md.
 */

import type { RequestContext } from '../context';
import type { Decision } from '../config/types';

/** Exact paths that are always blocked. */
export const BLOCKED_EXACT_PATHS: readonly string[] = [
  '/.env',
  '/.env.local',
  '/.env.production',
  '/.env.backup',
  '/.htaccess',
  '/.htpasswd',
  '/.ds_store',
  '/.npmrc',
  '/.netrc',
  '/.bash_history',
  '/.travis.yml',
  '/.git-credentials',
  '/composer.lock',
  '/server-status',
  '/server-info',
  '/pma',
  '/myadmin',
  '/adminer',
  '/phpmyadmin',
  '/telescope/requests',
  '/actuator/env',
  '/wp-config.php.bak',
  '/wp-config.php.old',
  '/wp-config.php.save',
  '/wp-config.php.txt',
];

/** Path prefixes that are always blocked. */
export const BLOCKED_PATH_PREFIXES: readonly string[] = [
  '/.git/',
  '/.svn/',
  '/.hg/',
  '/.aws/',
  '/.ssh/',
  '/.vscode/',
  '/.idea/',
  '/phpmyadmin',
  '/pma/',
  '/myadmin',
  '/mysqladmin',
  '/adminer',
  '/vendor/phpunit',
  '/cgi-bin/',
  '/_ignition/',
  '/solr/',
  '/jenkins/',
];

/**
 * Backup and dump extensions. Only blocked when the file sits at the web root (one path
 * segment): deep paths like `/wp-content/uploads/2024/archive.zip` are frequently
 * legitimate downloads.
 */
export const BACKUP_EXTENSIONS: readonly string[] = [
  '.sql',
  '.sql.gz',
  '.bak',
  '.old',
  '.orig',
  '.swp',
  '.zip',
  '.tar',
  '.tar.gz',
  '.tgz',
  '.rar',
  '.7z',
  '.dump',
];

/** Precompiled once at module load, never per request. */
const SQL_INJECTION_RE =
  /\b(?:union\s+(?:all\s+)?select|select\s.+\sfrom\s|insert\s+into\s|information_schema|sleep\s*\(|benchmark\s*\()/i;
const XSS_RE = /(?:<script|javascript:|onerror\s*=|onload\s*=|<iframe|<svg\s+on)/i;
const TRAVERSAL_RE = /(?:\.\.\/|\.\.\\|%2e%2e[/\\%])/i;
const NULL_BYTE_RE = /\u0000|%00/i;

function isRootLevelBackupFile(pathDecoded: string): boolean {
  // Exactly one leading slash and no further separators -> a web-root file.
  if (pathDecoded.indexOf('/', 1) !== -1) return false;
  for (let i = 0; i < BACKUP_EXTENSIONS.length; i++) {
    if (pathDecoded.endsWith(BACKUP_EXTENSIONS[i] as string)) return true;
  }
  return false;
}

/** Sensitive-file and scanner-path rules. Returns null when nothing matches. */
export function evaluateScannerPaths(ctx: RequestContext): Decision | null {
  const site = ctx.site;
  const path = ctx.pathDecoded;

  for (let i = 0; i < site.extraBlockedPrefixes.length; i++) {
    if (path.startsWith(site.extraBlockedPrefixes[i] as string)) {
      return { ruleId: 'path.extraBlocked', action: 'block', status: 403, detail: path };
    }
  }

  if (!site.config.paths.blockScannerPaths) return null;

  for (let i = 0; i < BLOCKED_EXACT_PATHS.length; i++) {
    if (path === BLOCKED_EXACT_PATHS[i]) {
      return { ruleId: 'path.sensitiveFile', action: 'block', status: 403, detail: path };
    }
  }
  for (let i = 0; i < BLOCKED_PATH_PREFIXES.length; i++) {
    if (path.startsWith(BLOCKED_PATH_PREFIXES[i] as string)) {
      return { ruleId: 'path.scanner', action: 'block', status: 403, detail: path };
    }
  }
  if (isRootLevelBackupFile(path)) {
    return { ruleId: 'path.backupFile', action: 'block', status: 403, detail: path };
  }
  return null;
}

/**
 * Light request-anomaly checks. Deliberately simple; see the scope note at the top of the
 * file. A null byte or a traversal sequence in a URL is never legitimate traffic.
 */
export function evaluateAnomalies(ctx: RequestContext): Decision | null {
  const limits = ctx.site.config.paths;
  if (!limits.anomalyChecks) return null;

  const query = ctx.url.search;

  if (ctx.path.length > limits.maxPathLength) {
    return {
      ruleId: 'anomaly.pathTooLong',
      action: 'block',
      status: 414,
      detail: String(ctx.path.length),
    };
  }
  if (query.length > limits.maxQueryLength) {
    return {
      ruleId: 'anomaly.queryTooLong',
      action: 'block',
      status: 414,
      detail: String(query.length),
    };
  }
  if (NULL_BYTE_RE.test(ctx.path) || NULL_BYTE_RE.test(query)) {
    return { ruleId: 'anomaly.nullByte', action: 'block', status: 400 };
  }
  if (TRAVERSAL_RE.test(ctx.path) || TRAVERSAL_RE.test(ctx.pathDecoded)) {
    return { ruleId: 'anomaly.traversal', action: 'block', status: 400 };
  }
  if (query.length > 0) {
    const decodedQuery = decodeSafely(query);
    if (XSS_RE.test(decodedQuery)) {
      return { ruleId: 'anomaly.xssPattern', action: 'block', status: 403 };
    }
    if (SQL_INJECTION_RE.test(decodedQuery)) {
      return { ruleId: 'anomaly.sqlPattern', action: 'block', status: 403 };
    }
  }
  return null;
}

function decodeSafely(value: string): string {
  try {
    // `+` means space in a query string; normalise it so `union+select` is caught.
    return decodeURIComponent(value.replace(/\+/g, ' '));
  } catch {
    return value;
  }
}
