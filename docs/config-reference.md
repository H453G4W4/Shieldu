# Configuration reference

Every configuration key, its type, its default and what it does.

Configuration comes from two layers, deep-merged at request time:

1. **Static** — `src/config/sites.ts` (per site) and `src/config/defaults.ts` (baseline).
2. **Dynamic** — KV namespace `SHIELD_CONFIG`:
   - `site:<hostname>` → a partial `SiteConfig`, merged over the matching static entry
   - `global` → a partial `GlobalConfig`

## Merge rules

| Case | Behaviour |
| --- | --- |
| Nested object | merged key by key |
| Array | **replaced wholesale** — an override array is the complete new value |
| `null` | meaningful: disables a rate limit group, clears an optional policy |
| Missing / `undefined` | leaves the base value alone |
| Unknown key | ignored |
| Type mismatch with the default | ignored, base value kept |

The last two rules are why a malformed KV entry degrades to the static config instead of
corrupting it. They also mean **an override can only set a key that exists in
`defaults.ts`** — that is why nullable fields are used instead of optional ones.

---

## `GlobalConfig`

KV key `global`. Applies to every site.

| Key | Type | Default | Effect |
| --- | --- | --- | --- |
| `configTtlSeconds` | `number` | `60` | How long a merged config is cached in module scope. Lower = faster propagation, more KV reads. |
| `allow` | `ListConfig` | empty | Allow list applied to every site, merged with the site's own. |
| `block` | `ListConfig` | empty | Block list applied to every site, merged with the site's own. |
| `adminAllowIp` | `string[]` | `[]` | When non-empty, only these IPs/CIDRs may call `/__shield/api/*`. |
| `version` | `string` | `"0.1.0"` | Reported by `/__shield/health`. Bump it when deploying a meaningful change. |

---

## `SiteConfig`

KV key `site:<hostname>`.

### Identity and posture

| Key | Type | Default | Effect |
| --- | --- | --- | --- |
| `hosts` | `string[]` | `[]` | Hostnames this entry applies to, lowercase, no port. A static entry with no hosts matches nothing. |
| `type` | `"wordpress" \| "generic"` | `"generic"` | `"wordpress"` runs the WordPress rule group; `"generic"` runs WordPress-*probe* detection instead. |
| `mode` | `"monitor" \| "enforce"` | `"monitor"` | `"monitor"` downgrades every blocking action to log-only. Start here. |
| `failClosed` | `boolean` | `false` | On an unexpected error: `false` forwards to the origin, `true` returns 503. |
| `logAllowed` | `boolean` | `false` | Also log allowed requests. Very noisy — debugging only. |
| `debugHeaders` | `boolean` | `false` | Add `X-Shield-Rule` / `X-Shield-Detail` to block responses. Leaks rule details; debugging only. |

### `allow` and `block` — `ListConfig`

| Key | Type | Default | Effect |
| --- | --- | --- | --- |
| `ip` | `string[]` | `[]` | IPv4/IPv6 addresses **and** CIDRs, mixed freely. A bare address is a single host. |
| `cidr` | `string[]` | `[]` | Same as `ip`; kept separate only for readability. Both are compiled into one list. |
| `asn` | `number[]` | `[]` | Autonomous system numbers, e.g. `14061`. |
| `country` | `string[]` | `[]` | ISO 3166-1 alpha-2 codes, uppercase. |

The **allow list wins over every block rule** in the pipeline. Put your own address in
`allow.ip` before anything else — it is your way back in when a rule turns out wrong.

Invalid entries are dropped when the list is compiled. The admin API rejects them up front
instead, so a typo does not silently become a rule that never fires.

| Key | Type | Default | Effect |
| --- | --- | --- | --- |
| `countryMode` | `"block" \| "allow"` | `"block"` | `"block"`: the countries in `block.country` are blocked. `"allow"`: only the countries in `allow.country` may enter — everyone else, **including an unknown country**, is blocked. |

> `countryMode: "allow"` is the one place where missing `request.cf` data changes the
> outcome. In production `request.cf` is always present; in local dev it is not.

### `methods` — `MethodConfig`

| Key | Type | Default | Effect |
| --- | --- | --- | --- |
| `blocked` | `string[]` | `["TRACE","TRACK","CONNECT"]` | Always blocked (405). |
| `allowed` | `string[] \| null` | `null` | When non-null, **only** these methods are allowed; everything else is 405. |

> The Workers runtime rejects `TRACK` and `CONNECT` before a Worker ever sees them. They
> stay in the default list as defence in depth.

### `paths` — `PathConfig`

| Key | Type | Default | Effect |
| --- | --- | --- | --- |
| `blockScannerPaths` | `boolean` | `true` | Apply the built-in sensitive-file and scanner-path lists (`src/engine/paths.ts`). |
| `extraBlockedPrefixes` | `string[]` | `[]` | Extra lowercase path prefixes to block, matched with `startsWith`. Checked even when `blockScannerPaths` is off. |
| `extraAllowedPaths` | `string[]` | `[]` | Exact lowercase paths that skip the path, WordPress and user-agent groups. They do **not** skip the IP/ASN/country block lists. |
| `anomalyChecks` | `boolean` | `true` | Length limits, null bytes, traversal, obvious XSS/SQL patterns in the query string. |
| `maxPathLength` | `number` | `1024` | Longer paths are rejected with 414. |
| `maxQueryLength` | `number` | `2048` | Longer query strings are rejected with 414. |

Built-in lists (all in `src/engine/paths.ts`, one place to extend):

- **Exact paths** — `/.env`, `/.htaccess`, `/.htpasswd`, `/.npmrc`, `/.netrc`,
  `/.git-credentials`, `/server-status`, `/actuator/env`, `/wp-config.php.bak`, ...
- **Prefixes** — `/.git/`, `/.svn/`, `/.hg/`, `/.aws/`, `/.ssh/`, `/phpmyadmin`, `/pma/`,
  `/adminer`, `/vendor/phpunit`, `/cgi-bin/`, `/_ignition/`, `/solr/`, `/jenkins/`, ...
- **Backup extensions at the web root only** — `.sql`, `.bak`, `.old`, `.orig`, `.zip`,
  `.tar.gz`, `.tgz`, `.dump`, ... Only one path segment deep, so
  `/wp-content/uploads/2026/gallery.zip` stays downloadable.

Paths are matched against the **lowercased, percent-decoded** pathname, so `/%2egit/config`
is caught the same as `/.git/config`.

### `userAgents` — `UserAgentConfig`

| Key | Type | Default | Effect |
| --- | --- | --- | --- |
| `blockKnownScanners` | `boolean` | `true` | Block `sqlmap`, `nikto`, `masscan`, `nmap`, `zgrab`, `dirbuster`, `wpscan`, `nuclei`, ... |
| `blockEmpty` | `boolean` | `false` | Block requests with an empty or missing `User-Agent`. |
| `blockGenericClients` | `boolean` | `false` | Block `curl`, `wget`, `python-requests`, `Go-http-client`, `okhttp`, ... Turn this on only if nothing legitimate calls the site from a script. |
| `extraBlocked` | `string[]` | `[]` | Extra substrings to block, matched case-insensitively. |
| `allowGoodBots` | `boolean` | `true` | Never apply any UA rule to a well-known crawler. **Keep this on.** |

> The `User-Agent` header is trivially spoofed. These rules cut scanner noise out of the
> logs; they are not a security boundary. The good-bot list is best effort for the same
> reason — use Cloudflare's Verified Bots signal in a WAF rule if you need certainty.

### `wordpress` — `WordPressConfig`

Only applied when `type === "wordpress"`.

| Key | Type | Default | Effect |
| --- | --- | --- | --- |
| `allowXmlrpc` | `boolean` | `false` | `false` blocks `/xmlrpc.php` outright. `true` allows it but meters it through the `xmlrpc` rate limit. **Turn on if you use Jetpack, the WordPress mobile app, or a WooCommerce integration that needs it.** |
| `loginAllowlistIp` | `string[]` | `[]` | When non-empty, only these IPs/CIDRs may reach `wp-login.php` and `/wp-admin/*`. |
| `loginAllowlistCountry` | `string[]` | `[]` | Same, by country. **Either list grants access** — so an admin who travels can be covered by country while the office keeps a fixed-IP entry. |
| `allowExternalCron` | `boolean` | `false` | `false` blocks `/wp-cron.php` from the outside. WordPress's own internal cron is a loopback request from the origin and never passes through Cloudflare, so blocking it is safe **unless you use an external cron service** — then turn this on. |
| `blockRestApiPublic` | `boolean` | `false` | Block `/wp-json/` entirely for logged-out visitors. Off by default: Gutenberg, many themes and every headless setup need the REST API. |
| `blockUserEnumeration` | `boolean` | `true` | Block `?author=<numeric id>` and unauthenticated `/wp-json/wp/v2/users*`. |
| `blockAuthorArchives` | `boolean` | `false` | Block `/author/*`. Off by default: author archives are legitimate pages on most blogs. |
| `allowInstaller` | `boolean` | `false` | Allow `install.php`, `upgrade.php`, `setup-config.php`. Only turn on during a migration, then turn it back off. |
| `rateLimitComments` | `boolean` | `true` | Meter `POST /wp-comments-post.php` through the `comments` rate limit. |

Rules that are **not** configurable, because they should never be off:

- `/wp-admin/admin-ajax.php` and `/wp-admin/admin-post.php` are exempt from every
  wp-admin rule. Logged-out visitors legitimately use both (forms, carts, search).
- `wp-config.php`, `wp-config-sample.php`, `readme.html`, `license.txt` and
  `wp-content/debug.log` are always blocked.
- `.php` / `.phtml` / `.php5` / `.phar` under `/wp-content/uploads/` is always blocked —
  uploads are user-controlled, so a PHP file there is a shell or a misconfiguration.
- `.php` under `/wp-includes/` is always blocked — it is never meant to be requested
  directly, and it is where the historical RFI/LFI chains lived.

**The "logged in" heuristic.** The user-enumeration and REST exemptions treat the presence
of a `wordpress_logged_in_*` cookie as "logged in". The edge cannot validate that cookie
(that needs the site's AUTH salts), so it is a **convenience heuristic, not a security
boundary** — someone who forges the cookie only skips a couple of enumeration rules, and
WordPress itself still authenticates the request.

| Key | Type | Default | Effect |
| --- | --- | --- | --- |
| `blockWordpressProbes` | `boolean` | `true` | For `type: "generic"` sites: treat `/wp-login.php`, `/xmlrpc.php`, `/wp-admin/`, `/wp-content/`, `/wp-json/` etc. as scanner probes. |

### `rateLimits` — `Record<group, RateLimitSetting | null>`

Groups: `login`, `xmlrpc`, `comments`, `general`.

| Key | Type | Default | Effect |
| --- | --- | --- | --- |
| `login` | `RateLimitSetting \| null` | `{limit: 5, period: 60}` | `POST wp-login.php` and `POST /wp-admin/*`. |
| `xmlrpc` | `RateLimitSetting \| null` | `{limit: 5, period: 60}` | `/xmlrpc.php`, when `allowXmlrpc` is on. |
| `comments` | `RateLimitSetting \| null` | `{limit: 10, period: 60}` | `POST /wp-comments-post.php`. |
| `general` | `RateLimitSetting \| null` | `null` | Optional per-IP burst limit for the whole site. Off by default. |

`RateLimitSetting`:

| Key | Type | Default | Effect |
| --- | --- | --- | --- |
| `limit` | `number` | per group | **Mirror** of the binding's `simple.limit` in `wrangler.jsonc`. |
| `period` | `10 \| 60` | `60` | **Mirror** of the binding's `simple.period`. Cloudflare allows only 10 or 60. |
| `retryAfterSeconds` | `number \| null` | `null` | Value for the `Retry-After` header. `null` uses `period`. |

> **Read this twice.** `limit` and `period` are **not** enforced from here. Cloudflare's
> `ratelimits` binding takes them from `wrangler.jsonc` at deploy time; the runtime API
> only accepts a key. These fields exist so the logs and the `Retry-After` header report
> the real numbers. Keep them in sync with `wrangler.jsonc`, or the logs will lie.
>
> Setting a group to `null` **does** disable it for that site — that part is enforced here.

Counter key: `<group>:<hostname>:<client ip>`. Counters are per Cloudflare location, so
the effective global limit is approximate. A missing or throwing binding fails open.

### `headers` — `HeadersConfig`

Applied to origin responses only, never to block pages. The status code is never changed
and `Set-Cookie` is never touched.

| Key | Type | Default | Effect |
| --- | --- | --- | --- |
| `hsts` | `boolean` | `false` | Send `Strict-Transport-Security`. Opt-in: browsers cache it, so a mistake is hard to undo. |
| `hstsIncludeSubdomains` | `boolean` | `false` | Add `includeSubDomains`. **Separate opt-in — this breaks any subdomain that is HTTP-only.** |
| `hstsMaxAge` | `number` | `15552000` (180 d) | `max-age` value. |
| `hstsPreload` | `boolean` | `false` | Add `preload`. Ignored unless `hstsIncludeSubdomains` is also on, because `preload` without it is meaningless. Only enable if you intend to submit to the preload list. |
| `nosniff` | `boolean` | `true` | Send `X-Content-Type-Options: nosniff`. |
| `frameAncestors` | `string` | `"'self'"` | CSP `frame-ancestors` value. `'self'` also emits `X-Frame-Options: SAMEORIGIN`; `'none'` emits `DENY`; a multi-origin list emits no `X-Frame-Options` (it has no multi-origin form). |
| `cspReportOnly` | `boolean` | `true` | Send the CSP as `Content-Security-Policy-Report-Only`. Default true because WordPress plugins routinely inject inline scripts. |
| `csp` | `string \| null` | `null` | Full policy string. `null` emits only a `frame-ancestors` directive. `frame-ancestors` is appended automatically unless the policy already contains it. |
| `referrerPolicy` | `string` | `"strict-origin-when-cross-origin"` | Empty string disables the header. |
| `permissionsPolicy` | `string` | conservative deny list | Empty string disables the header. |
| `coop` | `string \| null` | `"same-origin"` | `Cross-Origin-Opener-Policy`. `null` leaves the header alone. |
| `removeXPoweredBy` | `boolean` | `true` | Strip `X-Powered-By`, `X-AspNet-Version`, `X-AspNetMvc-Version`. |

A CSP the origin **already** sends is never overwritten: two CSP headers are intersected
by the browser, which silently breaks pages.

### `challenge` — `ChallengeConfig` (optional, off by default)

| Key | Type | Default | Effect |
| --- | --- | --- | --- |
| `enabled` | `boolean` | `false` | Turn the Turnstile challenge action on. |
| `ttlSeconds` | `number` | `3600` | How long a solved challenge is remembered. |
| `cookieName` | `string` | `"shield_clearance"` | Name of the signed clearance cookie. |
| `challengeRules` | `string[]` | `[]` | Rule ids or id **prefixes** that show a challenge instead of blocking, e.g. `["wp.login", "ua."]`. Rules not listed still block outright. |

Requires three values:

```sh
npx wrangler secret put SHIELD_COOKIE_SECRET   # HMAC key for the clearance cookie
npx wrangler secret put TURNSTILE_SECRET_KEY   # Turnstile siteverify secret
# TURNSTILE_SITE_KEY is public and can live in `vars` in wrangler.jsonc
```

The clearance cookie is `<expiry>.<HMAC-SHA256(expiry + "." + client ip)>`, set
`HttpOnly; Secure; SameSite=Lax`. Binding the signature to the IP makes a stolen cookie
useless from another address. Verifying a Turnstile token costs one subrequest, which is
why the challenge is only ever taken on the interstitial itself.

---

## Rule ids

Every rule has a stable id, which is what appears in the `ruleId` field of a log line.

| Id | Fires when |
| --- | --- |
| `default.allow` | nothing matched |
| `list.allow.ip` / `.asn` / `.country` | the allow list matched |
| `list.block.ip` / `.asn` / `.country` | the block list matched |
| `list.allowMode.country` | `countryMode: "allow"` and the country is not listed |
| `method.blocked` | the method is in `methods.blocked` |
| `method.notAllowed` | `methods.allowed` is set and the method is not in it |
| `path.extraBlocked` | `paths.extraBlockedPrefixes` matched |
| `path.sensitiveFile` | an exact sensitive path matched |
| `path.scanner` | a scanner path prefix matched |
| `path.backupFile` | a backup/dump extension at the web root |
| `anomaly.pathTooLong` / `.queryTooLong` | over the configured length limit |
| `anomaly.nullByte` / `.traversal` | null byte or `../` in the URL |
| `anomaly.xssPattern` / `.sqlPattern` | obvious injection pattern in the query string |
| `wp.xmlrpc.blocked` / `wp.xmlrpc.rateLimit` | xmlrpc blocked, or metered when allowed |
| `wp.installer` | `install.php` / `upgrade.php` / `setup-config.php` |
| `wp.exposedFile` | `wp-config.php`, `readme.html`, `debug.log`, ... |
| `wp.includesPhp` | direct `.php` under `/wp-includes/` |
| `wp.uploadsPhp` | `.php` under `/wp-content/uploads/` |
| `wp.cron` | external `wp-cron.php` while `allowExternalCron` is off |
| `wp.login.allowlist` | login/admin request from outside the allow lists |
| `wp.login.rateLimit` | `POST` to login/admin over the `login` limit |
| `wp.comments.rateLimit` | `POST /wp-comments-post.php` over the `comments` limit |
| `wp.restApi.public` | `/wp-json/` while `blockRestApiPublic` is on |
| `wp.userEnum.query` / `wp.userEnum.rest` | user enumeration |
| `wp.authorArchive` | `/author/*` while `blockAuthorArchives` is on |
| `wp.probe` | a WordPress path on a `generic` site |
| `ua.scanner` / `ua.genericClient` / `ua.empty` / `ua.extraBlocked` | user-agent rules |
| `rateLimit.general` | the optional site-wide burst limit |
| `challenge.cleared` | a valid Turnstile clearance cookie let the request through |

Non-decision log lines carry an `event` field instead: `host.unconfigured`,
`handler.error`, `ratelimit.bindingMissing`, `ratelimit.error`, `challenge.verifyFailed`,
`admin.authFailed`, `admin.ipDenied`, `admin.listWrite`, `admin.modeWrite`,
`admin.overrideDeleted`, `admin.error`.
