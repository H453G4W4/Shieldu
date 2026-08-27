/**
 * Shared configuration and decision types for edge-shield.
 *
 * Everything here is plain data so that a partial `SiteConfig` can be shipped as JSON in
 * a KV value and deep-merged over the static configuration without any runtime schema
 * library (the project has zero runtime dependencies).
 */

/** How a site is treated by the WordPress-specific rule group. */
export type SiteType = 'wordpress' | 'generic';

/**
 * `monitor` downgrades every blocking action to a log-only action. It is the
 * recommended starting point for a new site: roll out, read the logs, then switch to
 * `enforce`.
 */
export type SiteMode = 'monitor' | 'enforce';

/** The action a rule asks the pipeline to take. */
export type RuleAction = 'allow' | 'block' | 'monitor' | 'rateLimit' | 'challenge';

/** Rate limit groups. Each maps to one `ratelimits` binding in wrangler.jsonc. */
export type RateLimitGroup = 'login' | 'xmlrpc' | 'comments' | 'general';

/** `block` = the listed countries are blocked. `allow` = only listed countries may enter. */
export type CountryMode = 'block' | 'allow';

/** A single allow/block list. `ip` accepts bare addresses and CIDRs interchangeably. */
export interface ListConfig {
  /** IPv4/IPv6 addresses and/or CIDR blocks, mixed freely. */
  ip: string[];
  /** Kept separate purely for readability; merged with `ip` when compiled. */
  cidr: string[];
  /** Autonomous system numbers, e.g. 14061 (DigitalOcean). */
  asn: number[];
  /** ISO 3166-1 alpha-2 country codes, uppercase. */
  country: string[];
}

/**
 * Rate limit settings for one group.
 *
 * IMPORTANT: `limit` and `period` are NOT enforced from here. Cloudflare's `ratelimits`
 * binding takes its limit and period from `wrangler.jsonc` at deploy time; the runtime
 * API only accepts a key. These fields therefore mirror the binding configuration so
 * that logs and the `Retry-After` header are accurate. Keep them in sync with
 * `wrangler.jsonc`, or the numbers in the logs will lie. Setting a group to `null`
 * disables it for the site.
 */
export interface RateLimitSetting {
  /** Mirror of the binding's `simple.limit` in wrangler.jsonc. */
  limit: number;
  /** Mirror of the binding's `simple.period`. Cloudflare only allows 10 or 60. */
  period: 10 | 60;
  /**
   * Value used for the `Retry-After` header. `null` means "use `period`".
   *
   * It is a nullable field rather than an optional one on purpose: the KV deep merge only
   * writes keys that already exist in the defaults, so an optional key could never be set
   * from an override.
   */
  retryAfterSeconds: number | null;
}

export type RateLimitConfig = Record<RateLimitGroup, RateLimitSetting | null>;

/**
 * WordPress hardening flags. Every rule is a flag because a WordPress site can legitimately
 * depend on almost any of these endpoints (Jetpack, WooCommerce, headless front-ends,
 * external cron services, page builders that inject inline scripts, ...).
 */
export interface WordPressConfig {
  /** xmlrpc.php is blocked unless this is true. Jetpack and the WP mobile app need it. */
  allowXmlrpc: boolean;
  /** If non-empty, only these IPs/CIDRs may reach wp-login.php and /wp-admin/*. */
  loginAllowlistIp: string[];
  /** If non-empty, only these countries may reach wp-login.php and /wp-admin/*. */
  loginAllowlistCountry: string[];
  /** wp-cron.php from the outside is blocked unless this is true. */
  allowExternalCron: boolean;
  /** Block /wp-json/ entirely. Off by default: many themes and blocks need the REST API. */
  blockRestApiPublic: boolean;
  /** Block ?author=<n> and unauthenticated /wp-json/wp/v2/users*. */
  blockUserEnumeration: boolean;
  /** Block /author/* archives. Off by default: they are legitimate pages on many sites. */
  blockAuthorArchives: boolean;
  /** Allow install.php / upgrade.php / setup-config.php. Only turn on during a migration. */
  allowInstaller: boolean;
  /** Rate-limit POST /wp-comments-post.php via the `comments` group. */
  rateLimitComments: boolean;
}

/** Response security headers applied to origin responses only, never to block pages. */
export interface HeadersConfig {
  /** Send Strict-Transport-Security. Opt-in: it is hard to undo once cached by browsers. */
  hsts: boolean;
  /** Add `includeSubDomains`. Dangerous if any subdomain is HTTP-only. Separate opt-in. */
  hstsIncludeSubdomains: boolean;
  /** max-age in seconds. Default is 6 months. */
  hstsMaxAge: number;
  /** Add `preload`. Only enable if you intend to submit to the HSTS preload list. */
  hstsPreload: boolean;
  /** Send X-Content-Type-Options: nosniff. */
  nosniff: boolean;
  /**
   * CSP `frame-ancestors` value, also mapped to a matching `X-Frame-Options` header.
   * Use `"'self'"`, `"'none'"`, or a space-separated origin list.
   */
  frameAncestors: string;
  /**
   * Send the CSP as `Content-Security-Policy-Report-Only` instead of enforcing it.
   * Default true: WordPress plugins routinely inject inline scripts and styles.
   */
  cspReportOnly: boolean;
  /**
   * Full CSP policy string. When null, only a `frame-ancestors` directive is emitted.
   * `frame-ancestors` is appended automatically when the policy does not contain it.
   */
  csp: string | null;
  referrerPolicy: string;
  permissionsPolicy: string;
  /** Cross-Origin-Opener-Policy value, or null to leave the header alone. */
  coop: string | null;
  /** Strip `X-Powered-By` (and `X-AspNet-Version`) from origin responses. */
  removeXPoweredBy: boolean;
}

/** Generic (non-WordPress-specific) path rules. */
export interface PathConfig {
  /** Apply the built-in sensitive-file and scanner-path list. */
  blockScannerPaths: boolean;
  /** Extra path prefixes to block, lowercase, matched with `startsWith`. */
  extraBlockedPrefixes: string[];
  /** Extra exact paths that are always allowed, checked before every path rule. */
  extraAllowedPaths: string[];
  /** Light request-anomaly checks (length, null bytes, traversal, obvious injection). */
  anomalyChecks: boolean;
  maxPathLength: number;
  maxQueryLength: number;
}

/** HTTP method rules. */
export interface MethodConfig {
  /** Methods that are always blocked. Uppercase. */
  blocked: string[];
  /** When non-null, ONLY these methods are allowed. Uppercase. */
  allowed: string[] | null;
}

/** User-agent rules. UA is trivially spoofed; treat these as noise reduction, not security. */
export interface UserAgentConfig {
  /** Block obvious offensive-security tooling (sqlmap, nikto, nmap, ...). */
  blockKnownScanners: boolean;
  /** Block requests with an empty or missing User-Agent. Off by default. */
  blockEmpty: boolean;
  /** Block generic HTTP clients (curl, python-requests, Go-http-client). Off by default. */
  blockGenericClients: boolean;
  /** Extra lowercase substrings to block. */
  extraBlocked: string[];
  /** Never apply UA rules to well-known search engine crawlers. Keep this on. */
  allowGoodBots: boolean;
}

/** Optional Turnstile challenge action (phase 4). Off by default. */
export interface ChallengeConfig {
  enabled: boolean;
  /** How long a solved challenge is remembered, in seconds. */
  ttlSeconds: number;
  /** Cookie name for the signed challenge clearance. */
  cookieName: string;
}

/** Per-site configuration. Every field is required after merging with the defaults. */
export interface SiteConfig {
  /** Hostnames this entry applies to, lowercase, no port. */
  hosts: string[];
  type: SiteType;
  mode: SiteMode;
  /** When true, an unexpected error returns 503 instead of forwarding to the origin. */
  failClosed: boolean;
  allow: ListConfig;
  block: ListConfig;
  countryMode: CountryMode;
  methods: MethodConfig;
  paths: PathConfig;
  userAgents: UserAgentConfig;
  wordpress: WordPressConfig;
  /** For `type: "generic"`: treat /wp-login.php, /xmlrpc.php etc. as scanner probes. */
  blockWordpressProbes: boolean;
  rateLimits: RateLimitConfig;
  headers: HeadersConfig;
  challenge: ChallengeConfig;
  /** Emit a log line for allowed requests too. Very noisy; for debugging only. */
  logAllowed: boolean;
  /** Expose the matched rule id on block responses. Leaks rule details; debugging only. */
  debugHeaders: boolean;
}

/** A partial site config, as stored in KV under `site:<hostname>`. */
export type SiteConfigOverride = DeepPartial<SiteConfig>;

/** Account-wide configuration, overridable from KV under the `global` key. */
export interface GlobalConfig {
  /** How long a merged config is cached in module scope, in seconds. */
  configTtlSeconds: number;
  /** Applied to every site, before the per-site allow list. */
  allow: ListConfig;
  /** Applied to every site, before the per-site block list. */
  block: ListConfig;
  /** Admin API: when non-empty, only these IPs/CIDRs may call /__shield/api/*. */
  adminAllowIp: string[];
  /** Reported by /__shield/health. Bump it when deploying a meaningful change. */
  version: string;
}

export type GlobalConfigOverride = DeepPartial<GlobalConfig>;

/**
 * Deep-partial helper. Arrays are replaced wholesale by the merge, never merged
 * element-wise, so an override array is always the complete new value.
 */
export type DeepPartial<T> = {
  [K in keyof T]?: T[K] extends readonly unknown[]
    ? T[K]
    : T[K] extends object | null
      ? T[K] extends null
        ? T[K]
        : DeepPartial<NonNullable<T[K]>> | null
      : T[K];
};

/** The outcome of evaluating the rule pipeline. */
export interface Decision {
  /** Stable rule identifier, e.g. `wp.xmlrpc` or `list.block.asn`. Always present. */
  ruleId: string;
  action: RuleAction;
  /** HTTP status to return when the action blocks. 200 for `allow`. */
  status: number;
  /** Seconds for the `Retry-After` header on a 429. */
  retryAfterSeconds?: number;
  /** Short machine-readable detail, e.g. the ASN or country that matched. */
  detail?: string;
}

/** Worker bindings. Keep in sync with wrangler.jsonc. */
export interface Env {
  /** KV namespace holding dynamic config overrides. Optional: missing = static only. */
  SHIELD_CONFIG?: KVNamespace;
  RL_LOGIN?: RateLimit;
  RL_XMLRPC?: RateLimit;
  RL_COMMENTS?: RateLimit;
  RL_GENERAL?: RateLimit;
  /** Bearer token for /__shield/api/*. Set with `wrangler secret put SHIELD_ADMIN_TOKEN`. */
  SHIELD_ADMIN_TOKEN?: string;
  /** HMAC key for the Turnstile clearance cookie. Only needed when challenge is enabled. */
  SHIELD_COOKIE_SECRET?: string;
  TURNSTILE_SITE_KEY?: string;
  TURNSTILE_SECRET_KEY?: string;
}

/**
 * Cloudflare's rate limiting binding.
 *
 * Verified against developers.cloudflare.com (Workers -> Runtime APIs -> Bindings ->
 * Rate Limiting): the binding is configured in wrangler.jsonc with a `namespace_id` and
 * a `simple` block (`limit`, and `period` which must be 10 or 60), requires Wrangler
 * >= 4.36.0, and exposes a single `limit({ key })` method. Counters are maintained per
 * Cloudflare location, so the effective limit is approximate.
 */
export interface RateLimit {
  limit(options: { key: string }): Promise<{ success: boolean }>;
}
