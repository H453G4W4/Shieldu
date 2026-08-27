/**
 * Global defaults. Every field of `SiteConfig` has a default here, so a static site entry
 * (and a KV override) only has to state what differs from the safe baseline.
 *
 * The baseline is deliberately conservative: nothing that could break a normal WordPress
 * install is on by default, and `mode` starts at `monitor`.
 */

import type { GlobalConfig, SiteConfig } from './types';

export const SHIELD_VERSION = '0.1.0';

export const defaultGlobalConfig: GlobalConfig = {
  configTtlSeconds: 60,
  allow: { ip: [], cidr: [], asn: [], country: [] },
  block: { ip: [], cidr: [], asn: [], country: [] },
  adminAllowIp: [],
  version: SHIELD_VERSION,
};

/**
 * Defaults for a single site. `hosts` is intentionally empty: a site entry without hosts
 * matches nothing, which is the safe failure mode for a malformed override.
 */
export const defaultSiteConfig: SiteConfig = {
  hosts: [],
  type: 'generic',
  mode: 'monitor',
  failClosed: false,

  allow: { ip: [], cidr: [], asn: [], country: [] },
  block: { ip: [], cidr: [], asn: [], country: [] },
  countryMode: 'block',

  methods: {
    // TRACE/TRACK enable cross-site tracing; CONNECT has no business reaching an origin.
    blocked: ['TRACE', 'TRACK', 'CONNECT'],
    allowed: null,
  },

  paths: {
    blockScannerPaths: true,
    extraBlockedPrefixes: [],
    extraAllowedPaths: [],
    anomalyChecks: true,
    maxPathLength: 1024,
    maxQueryLength: 2048,
  },

  userAgents: {
    blockKnownScanners: true,
    blockEmpty: false,
    blockGenericClients: false,
    extraBlocked: [],
    allowGoodBots: true,
  },

  wordpress: {
    allowXmlrpc: false,
    loginAllowlistIp: [],
    loginAllowlistCountry: [],
    allowExternalCron: false,
    // Off by default: Gutenberg, many themes and most headless setups need /wp-json/.
    blockRestApiPublic: false,
    blockUserEnumeration: true,
    // Off by default: /author/<slug>/ archives are legitimate pages on most blogs.
    blockAuthorArchives: false,
    allowInstaller: false,
    rateLimitComments: true,
  },

  blockWordpressProbes: true,

  // These mirror the `ratelimits` bindings declared in wrangler.jsonc. See the comment on
  // `RateLimitSetting` in types.ts: the numbers are enforced by the binding, not here.
  rateLimits: {
    login: { limit: 5, period: 60 },
    xmlrpc: { limit: 5, period: 60 },
    comments: { limit: 10, period: 60 },
    general: null,
  },

  headers: {
    hsts: false,
    hstsIncludeSubdomains: false,
    hstsMaxAge: 15552000, // 180 days
    hstsPreload: false,
    nosniff: true,
    frameAncestors: "'self'",
    cspReportOnly: true,
    csp: null,
    referrerPolicy: 'strict-origin-when-cross-origin',
    permissionsPolicy: 'accelerometer=(), autoplay=(), camera=(), display-capture=(), encrypted-media=(), fullscreen=(self), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), midi=(), payment=(), usb=(), xr-spatial-tracking=()',
    coop: 'same-origin',
    removeXPoweredBy: true,
  },

  challenge: {
    enabled: false,
    ttlSeconds: 3600,
    cookieName: 'shield_clearance',
  },

  logAllowed: false,
  debugHeaders: false,
};
