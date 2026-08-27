/**
 * Static per-site configuration.
 *
 * These entries are the baseline. Anything stored in KV under `site:<hostname>` is deep
 * merged on top of the matching entry at runtime, so day-to-day list changes do not need
 * a redeploy (see `loader.ts` and the admin API).
 *
 * PLACEHOLDERS: replace the example hostnames, admin IPs and country lists with real
 * values before deploying. Every entry below starts in `mode: "monitor"` on purpose --
 * roll out, read the logs for a few days, then flip to `"enforce"`.
 *
 * ---------------------------------------------------------------------------------------
 * ADDING A REAL SITE
 *
 *   1. Copy one of the entries below and replace `hosts` with your hostnames, lowercase,
 *      no scheme, no port.
 *   2. Put YOUR OWN address in `allow.ip` first. The allow list beats every block rule, so
 *      it is your way back in when a rule turns out to be wrong.
 *   3. Add a matching route per hostname in wrangler.jsonc.
 *   4. Leave `mode: "monitor"`. Read the logs. Only then switch to `"enforce"`.
 *   5. Run `npm test`.
 *
 * Step 5 is not optional busywork. `test/validate.test.ts` runs `validateSites()` over
 * this file, because the runtime is deliberately forgiving: a malformed CIDR is dropped
 * silently rather than crashing the shield. That means a typo here fails OPEN --
 * a mistyped `block.ip` entry is a rule that never fires, and a mistyped
 * `wordpress.loginAllowlistIp` empties the list, which the login rule reads as
 * "no allow list configured" and lets everyone through. The test turns both into a
 * failing build instead of a silent hole.
 * ---------------------------------------------------------------------------------------
 */

import type { SiteConfig, DeepPartial } from './types';

/** A static entry only has to declare `hosts`; everything else falls back to the defaults. */
export type StaticSiteEntry = DeepPartial<SiteConfig> & { hosts: string[] };

export const sites: StaticSiteEntry[] = [
  {
    // PLACEHOLDER — a WordPress site.
    hosts: ['example.com', 'www.example.com'],
    type: 'wordpress',
    mode: 'monitor',
    failClosed: false,
    allow: {
      // PLACEHOLDER — put your office/VPN addresses here so a bad rule can never lock you
      // out. The allow list wins over every block rule below it.
      ip: ['203.0.113.10', '2001:db8::/32'],
      cidr: [],
      asn: [],
      country: [],
    },
    block: { ip: [], cidr: [], asn: [], country: [] },
    countryMode: 'block',
    wordpress: {
      allowXmlrpc: false,
      loginAllowlistIp: [],
      loginAllowlistCountry: [],
      allowExternalCron: false,
      blockRestApiPublic: false,
      blockUserEnumeration: true,
      blockAuthorArchives: false,
      allowInstaller: false,
      rateLimitComments: true,
    },
    rateLimits: {
      login: { limit: 5, period: 60 },
      xmlrpc: { limit: 5, period: 60 },
      comments: { limit: 10, period: 60 },
      general: null,
    },
    headers: {
      hsts: false,
      hstsIncludeSubdomains: false,
      cspReportOnly: true,
      frameAncestors: "'self'",
    },
    logAllowed: false,
  },
  {
    // PLACEHOLDER — a non-WordPress site. WordPress paths here are pure scanner traffic.
    hosts: ['app.example.net'],
    type: 'generic',
    mode: 'monitor',
    blockWordpressProbes: true,
    methods: {
      blocked: ['TRACE', 'TRACK', 'CONNECT'],
      allowed: null,
    },
    userAgents: {
      blockKnownScanners: true,
      blockEmpty: false,
      blockGenericClients: false,
      extraBlocked: [],
      allowGoodBots: true,
    },
    rateLimits: {
      login: null,
      xmlrpc: null,
      comments: null,
      general: null,
    },
    headers: {
      hsts: false,
      cspReportOnly: true,
      frameAncestors: "'self'",
    },
  },
];
