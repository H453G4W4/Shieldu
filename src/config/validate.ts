/**
 * Static configuration validation.
 *
 * Why this exists: the runtime is deliberately forgiving. `compileCidrList` silently drops
 * entries it cannot parse, because a malformed value arriving from KV must never crash the
 * shield. That forgiveness is dangerous for configuration you wrote by hand:
 *
 *   - a typo in `block.ip` produces a rule that never fires -- fail open;
 *   - a typo that empties `wordpress.loginAllowlistIp` makes the login allow list look
 *     absent, and an absent allow list means EVERYONE may reach wp-login.php. You would
 *     believe the admin area is locked down while it is wide open.
 *
 * So: forgiving at runtime, strict at author time. `npm test` runs this over every entry
 * in `sites.ts`, which turns those silent failures into a failing test.
 *
 * This is a build/test-time helper. Nothing in the request path calls it.
 */

import type { SiteConfig } from './types';
import { parseCidr } from '../engine/ip';

export interface ConfigProblem {
  /** Dotted path to the offending key, e.g. `sites[0].wordpress.loginAllowlistIp[1]`. */
  path: string;
  message: string;
}

const HOSTNAME_RE = /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*$/;
const COUNTRY_RE = /^[A-Z]{2}$/;

function checkCidrList(
  values: readonly string[],
  path: string,
  problems: ConfigProblem[],
): void {
  values.forEach((value, index) => {
    if (parseCidr(value) === null) {
      problems.push({
        path: `${path}[${index}]`,
        message: `"${value}" is not a valid IP address or CIDR block. It would be dropped silently at runtime.`,
      });
    }
  });
}

function checkCountryList(
  values: readonly string[],
  path: string,
  problems: ConfigProblem[],
): void {
  values.forEach((value, index) => {
    if (!COUNTRY_RE.test(value)) {
      problems.push({
        path: `${path}[${index}]`,
        message: `"${value}" is not an uppercase ISO 3166-1 alpha-2 country code.`,
      });
    }
  });
}

function checkAsnList(values: readonly number[], path: string, problems: ConfigProblem[]): void {
  values.forEach((value, index) => {
    if (!Number.isInteger(value) || value <= 0) {
      problems.push({
        path: `${path}[${index}]`,
        message: `${String(value)} is not a positive integer ASN.`,
      });
    }
  });
}

/** Validate one resolved site config. Returns every problem found, never throws. */
export function validateSiteConfig(config: SiteConfig, path: string): ConfigProblem[] {
  const problems: ConfigProblem[] = [];

  if (config.hosts.length === 0) {
    problems.push({ path: `${path}.hosts`, message: 'A site entry must declare at least one host.' });
  }
  config.hosts.forEach((host, index) => {
    const at = `${path}.hosts[${index}]`;
    if (host !== host.toLowerCase()) {
      problems.push({ path: at, message: `"${host}" must be lowercase; hosts are matched lowercased.` });
    } else if (!HOSTNAME_RE.test(host)) {
      problems.push({
        path: at,
        message: `"${host}" is not a bare hostname. No scheme, no port, no path, no wildcard.`,
      });
    }
  });

  for (const listName of ['allow', 'block'] as const) {
    const list = config[listName];
    checkCidrList(list.ip, `${path}.${listName}.ip`, problems);
    checkCidrList(list.cidr, `${path}.${listName}.cidr`, problems);
    checkCountryList(list.country, `${path}.${listName}.country`, problems);
    checkAsnList(list.asn, `${path}.${listName}.asn`, problems);
  }

  // A login allow list whose every entry is malformed compiles to an EMPTY list, and an
  // empty list means "no allow list", i.e. everyone is let through. Catching this is the
  // main reason this file exists.
  checkCidrList(
    config.wordpress.loginAllowlistIp,
    `${path}.wordpress.loginAllowlistIp`,
    problems,
  );
  checkCountryList(
    config.wordpress.loginAllowlistCountry,
    `${path}.wordpress.loginAllowlistCountry`,
    problems,
  );

  if (config.countryMode === 'allow' && config.allow.country.length === 0) {
    problems.push({
      path: `${path}.countryMode`,
      message: 'countryMode is "allow" but allow.country is empty, so the rule never applies.',
    });
  }

  for (const [group, setting] of Object.entries(config.rateLimits)) {
    if (setting === null) continue;
    const at = `${path}.rateLimits.${group}`;
    if (setting.period !== 10 && setting.period !== 60) {
      problems.push({
        path: `${at}.period`,
        message: `period must be 10 or 60 (Cloudflare allows nothing else); got ${String(setting.period)}.`,
      });
    }
    if (!Number.isInteger(setting.limit) || setting.limit <= 0) {
      problems.push({ path: `${at}.limit`, message: 'limit must be a positive integer.' });
    }
    if (setting.retryAfterSeconds !== null && setting.retryAfterSeconds <= 0) {
      problems.push({
        path: `${at}.retryAfterSeconds`,
        message: 'retryAfterSeconds must be a positive integer, or null to use `period`.',
      });
    }
  }

  config.methods.blocked.forEach((method, index) => {
    if (method !== method.toUpperCase()) {
      problems.push({
        path: `${path}.methods.blocked[${index}]`,
        message: `"${method}" should be uppercase.`,
      });
    }
  });

  // Paths are matched against the lowercased, percent-decoded pathname, so an entry that
  // is not lowercase or does not start with "/" can never match.
  config.paths.extraBlockedPrefixes.forEach((prefix, index) => {
    const at = `${path}.paths.extraBlockedPrefixes[${index}]`;
    if (!prefix.startsWith('/')) {
      problems.push({ path: at, message: `"${prefix}" must start with "/".` });
    }
    if (prefix !== prefix.toLowerCase()) {
      problems.push({ path: at, message: `"${prefix}" must be lowercase; paths are matched lowercased.` });
    }
  });
  config.paths.extraAllowedPaths.forEach((allowed, index) => {
    const at = `${path}.paths.extraAllowedPaths[${index}]`;
    if (!allowed.startsWith('/')) {
      problems.push({ path: at, message: `"${allowed}" must start with "/".` });
    }
    if (allowed !== allowed.toLowerCase()) {
      problems.push({ path: at, message: `"${allowed}" must be lowercase; paths are matched lowercased.` });
    }
  });

  config.userAgents.extraBlocked.forEach((ua, index) => {
    if (ua.trim() === '') {
      problems.push({
        path: `${path}.userAgents.extraBlocked[${index}]`,
        message: 'An empty substring matches every user agent. Remove it.',
      });
    }
  });

  if (config.challenge.enabled && config.challenge.challengeRules.length === 0) {
    problems.push({
      path: `${path}.challenge`,
      message: 'challenge.enabled is true but challengeRules is empty, so no rule ever challenges.',
    });
  }

  if (config.headers.hstsPreload && !config.headers.hstsIncludeSubdomains) {
    problems.push({
      path: `${path}.headers.hstsPreload`,
      message: 'hstsPreload requires hstsIncludeSubdomains; the directive is dropped without it.',
    });
  }

  return problems;
}

/** Validate a whole set of resolved sites, including cross-entry hostname collisions. */
export function validateSites(configs: readonly SiteConfig[]): ConfigProblem[] {
  const problems: ConfigProblem[] = [];
  const seen = new Map<string, number>();

  configs.forEach((config, index) => {
    const path = `sites[${index}]`;
    problems.push(...validateSiteConfig(config, path));

    config.hosts.forEach((host, hostIndex) => {
      const key = host.toLowerCase();
      const previous = seen.get(key);
      if (previous !== undefined) {
        // The host index is built by iterating entries in order, so a duplicate means the
        // later entry silently wins and the earlier one is dead configuration.
        problems.push({
          path: `${path}.hosts[${hostIndex}]`,
          message: `"${host}" is already declared by sites[${previous}]; the later entry wins and the earlier one is dead.`,
        });
      } else {
        seen.set(key, index);
      }
    });
  });

  return problems;
}

/** Render problems as a readable multi-line report. */
export function formatProblems(problems: readonly ConfigProblem[]): string {
  return problems.map((problem) => `  ${problem.path}: ${problem.message}`).join('\n');
}
