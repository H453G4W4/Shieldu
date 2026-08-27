# edge-shield

One reusable Cloudflare Worker that sits in front of several origins as a programmable
security layer. Attach it to any proxied zone through a Worker route, give the hostname a
config entry, and it filters traffic before it ever reaches the origin.

Built for the **Workers Free plan** and the **Free zone plan**. Zero runtime dependencies,
TypeScript with `strict: true`.

---

## What it does

| Capability | Notes |
| --- | --- |
| IP / CIDR allow and block lists | IPv4 and IPv6, dependency-free matcher |
| ASN blocking | hosting providers, VPN exits, scanner networks |
| Country blocking **or** country allow-listing | `countryMode: "block" \| "allow"` |
| HTTP method rules | `TRACE`/`TRACK`/`CONNECT` blocked by default |
| Sensitive-file and scanner-path rules | `/.env`, `/.git/`, `/phpmyadmin`, backup dumps, ... |
| WordPress hardening | login, xmlrpc, user enumeration, uploads, installer, cron |
| User-agent rules | scanners blocked, search engines never touched |
| Rate limiting | login, xmlrpc, comments and an optional general burst limit |
| Response security headers | HSTS, CSP, frame-ancestors, Permissions-Policy, ... |
| Per-hostname configuration | static entries plus KV overrides, no redeploy needed |
| Monitor mode | log what *would* have been blocked, block nothing |
| Structured JSON logs | one line per decision, with the exact rule id |
| Optional Turnstile challenge | off by default |

### What it deliberately does not do

- **Deep payload inspection.** Cloudflare's managed WAF runs *before* Workers, costs
  nothing on the Free plan, and is far better at it. The anomaly checks here are cheap
  heuristics for obvious scanner noise. See `docs/cloudflare-setup.md`.
- **Bot verification.** The good-bot allow list matches on User-Agent, which anyone can
  spoof. Use Cloudflare's Verified Bots signal in a WAF rule if you need certainty.
- **Protect an origin that is reachable directly.** If someone can hit your origin IP, they
  bypass Cloudflare entirely, and this Worker with it. Locking the origin down is
  mandatory, not optional — see `docs/cloudflare-setup.md`.

---

## Decision pipeline

Ordered, **first match wins**, allow list first.

| # | Step | Outcome |
| --- | --- | --- |
| 1 | `/__shield/*` (health, admin API, Turnstile callback) | answered directly, never forwarded |
| 2 | Global + site **allow** list (ip, cidr, asn, country) | **ALLOW**, skipping every rule below |
| 3 | IP / CIDR block list | **BLOCK** |
| 4 | ASN block list | **BLOCK** |
| 5 | Country block list, or country allow mode | **BLOCK** |
| 6 | Method rules | **BLOCK** |
| 7 | Anomaly checks, then sensitive-path / scanner rules | **BLOCK** |
| 8 | WordPress rules, or WordPress-probe rules on a generic site | **BLOCK** or **RATE LIMIT** |
| 9 | User-agent rules | **BLOCK** |
| 10 | Optional `general` per-IP rate limit | **429** |
| 11 | Forward to the origin, then add security headers to the response | |

Steps 3–5 come out of one compiled list and are matched in a single pass; the rule id in
the log still says which of the three fired.

**Actions:** `allow`, `block`, `monitor`, `rateLimit`, `challenge` (optional).
Every rule carries a stable string id (`wp.xmlrpc.blocked`, `path.scanner`,
`list.block.asn`, ...) so a log line names exactly what fired.

**Monitor mode.** `mode: "monitor"` on a site downgrades every blocking action to
log-only: the log records what would have happened, and the request is forwarded anyway.
Security headers are still applied. This is how you roll a site out safely.

---

## Quick start

```sh
npm install

# 1. Log in and create the KV namespace for dynamic config.
npx wrangler login
npx wrangler kv namespace create SHIELD_CONFIG
#    -> copy the printed id into the kv_namespaces block in wrangler.jsonc

# 2. Set the admin API token (never write it to a file).
npx wrangler secret put SHIELD_ADMIN_TOKEN

# 3. Edit wrangler.jsonc: replace the placeholder routes with your real
#    hostnames and zone names.
# 4. Edit src/config/sites.ts: replace the placeholder hosts, admin IPs and
#    country lists.

npm run typecheck
npm test
npm run dev            # local, at http://localhost:8787
bash scripts/smoke.sh  # curl examples against wrangler dev

npx wrangler deploy    # when you are ready
```

> `wrangler deploy` is never run for you. Read the diff, then run it yourself.

### Adding a site

1. Add an entry to `src/config/sites.ts` with the hostnames and `type`
   (`"wordpress"` or `"generic"`). Everything you leave out falls back to the safe
   defaults in `src/config/defaults.ts`.
2. Add a route per hostname in `wrangler.jsonc`.
3. Put your own IP in `allow.ip` **before** anything else. The allow list beats every
   block rule, so it is your way back in if a rule turns out to be wrong.
4. Deploy with `mode: "monitor"`.
5. Watch the logs for a few days: `npx wrangler tail --format=pretty`.
6. When nothing legitimate is being flagged, switch to `enforce` — either in
   `sites.ts` (redeploy) or through the admin API (instant, no deploy).

### Rollout plan

```
monitor  ->  read logs  ->  fix false positives  ->  enforce
```

Every `monitored: true` line in the log is a request that *would* have been blocked.
Grep for them before flipping the switch:

```sh
npx wrangler tail --format=json | grep '"monitored":true'
```

---

## Configuration

Two layers, deep-merged at request time:

1. **Static** — `src/config/sites.ts`, part of the deployed bundle.
2. **Dynamic** — a KV namespace bound as `SHIELD_CONFIG`:
   - `site:<hostname>` → a partial `SiteConfig`, merged over the static entry
   - `global` → a partial `GlobalConfig`

Merge rules: objects merge key by key, **arrays replace wholesale**, `null` is meaningful
(it disables a rate limit group), and a value whose type does not match the default is
ignored rather than applied. A malformed KV entry therefore degrades to the static config
instead of corrupting it.

The merged config is cached in module scope for `configTtlSeconds` (default 60), so in
steady state a request does no I/O at all. A KV read failure falls back to the static
config; it never fails the request.

A hostname with **neither** a static entry nor a KV override is forwarded to the origin
untouched, and logged once per TTL window.

Every key is documented in **[`docs/config-reference.md`](docs/config-reference.md)**.

---

## Admin API

```
GET    /__shield/health                        no auth  -> {"ok":true,"version":"..."}
GET    /__shield/api/config?host=<host>        effective merged config
GET    /__shield/api/override?host=<host>      raw KV override
DELETE /__shield/api/override?host=<host>      delete the override
POST   /__shield/api/mode                      {host, mode?, countryMode?}
POST   /__shield/api/list                      {host, list, field, op, values}
```

Everything under `/__shield/api/` requires `Authorization: Bearer $SHIELD_ADMIN_TOKEN`
(compared in constant time), plus an optional IP allow list (`global.adminAllowIp` in KV)
and a rate limit on attempts. Without `SHIELD_ADMIN_TOKEN` set, the API returns 503 rather
than being open.

```sh
# Block a /24 on one site, right now, no deploy.
curl -sX POST https://example.com/__shield/api/list \
  -H "Authorization: Bearer $SHIELD_ADMIN_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"host":"example.com","list":"block","field":"ip","op":"add","values":["198.51.100.0/24"]}'

# Switch a site to enforce.
curl -sX POST https://example.com/__shield/api/mode \
  -H "Authorization: Bearer $SHIELD_ADMIN_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"host":"example.com","mode":"enforce"}'
```

A write invalidates the cache in the isolate that served it. Other isolates keep the
previous config until their TTL expires — so allow up to `configTtlSeconds` for a change
to be fully live everywhere.

---

## Rate limiting

Backed by Cloudflare's `ratelimits` binding (Wrangler ≥ 4.36.0). Four bindings are
declared in `wrangler.jsonc`: `RL_LOGIN`, `RL_XMLRPC`, `RL_COMMENTS`, `RL_GENERAL`. The
key is `<group>:<hostname>:<client ip>`, so one binding shared across sites never lets
traffic to one site consume another's budget. Exceeding a limit returns **429** with a
`Retry-After` header.

Two things to know:

- **The limit and period live in `wrangler.jsonc`, not in the site config.** The runtime
  API only takes a key; `limit` and `period` are fixed at deploy time (`period` must be
  exactly `10` or `60`). The numbers in `rateLimits` mirror them so that the logs and the
  `Retry-After` header are accurate — keep the two in sync, or the logs will lie. Setting
  a group to `null` disables it for that site.
- **Counters are per Cloudflare location**, so the effective global limit is approximate.
  That is fine for brute-force protection, which is all it is used for here. If you ever
  need exact counters, a SQLite-backed Durable Object (`new_sqlite_classes`) works on the
  Free plan — that is a deliberate future option, not built today.

A missing or throwing binding **fails open**: a broken rate limiter must not take the site
down with it.

---

## Logging

One JSON line per non-allow decision, written with `console.log`, so it lands in Workers
Logs (`observability` is enabled in `wrangler.jsonc`) and in `wrangler tail`.

```json
{"src":"shield","ts":"2026-08-27T10:00:00.000Z","host":"example.com","method":"POST",
 "path":"/xmlrpc.php","ip":"203.0.113.5","country":"NL","asn":14061,"asOrg":"DigitalOcean",
 "ua":"Mozilla/5.0 ...","ruleId":"wp.xmlrpc.blocked","action":"block","monitored":true,
 "mode":"monitor","status":403,"durationMs":0}
```

`logAllowed: false` by default — allowed requests are not logged. Set it to `true` on one
site temporarily when you are debugging, then turn it back off.

`durationMs` is measured with `Date.now()`, which the Workers runtime only advances on
I/O. For a request blocked without touching the origin it is usually `0`. That is expected;
treat it as a coarse signal.

For long-term aggregation, Analytics Engine is a good optional add-on (free tier
available) — write a datapoint alongside the log line.

---

## Design notes

**Client IP.** Only `CF-Connecting-IP` is ever read. `X-Forwarded-For` is
attacker-controlled and is deliberately not referenced anywhere in the codebase.

**Geo data.** `country`, `asn`, `asOrganization` and `isEUCountry` come from `request.cf`,
which is absent in local dev. Every field is read defensively; unknown geo data simply
means the geo rules cannot match. The one exception is `countryMode: "allow"`, where an
unknown country cannot satisfy the allow list and is therefore blocked.

**Fail open.** The whole handler is wrapped in try/catch. An unexpected error forwards the
request to the origin unchanged. Per-site `failClosed: true` returns 503 instead — use it
only where an unfiltered request is worse than an outage.

**CPU budget.** The Free plan allows roughly 10 ms of CPU per invocation. Regexes are
compiled at module load, config is compiled once per TTL window, list matching is byte
comparisons and `Set` lookups, and there is no per-request network call other than a
memory-cached KV read.

**Response bodies are never buffered.** Security headers are added by constructing a new
`Response` around the original body stream.

**WordPress endpoints that must never break** are hard-coded exemptions, not flags:
`/wp-admin/admin-ajax.php` and `/wp-admin/admin-post.php` are checked before any wp-admin
rule can reach them, because logged-out visitors legitimately use both.

---

## Free plan limits

The Workers Free plan allows **100,000 requests per day**, resetting at midnight UTC, and
**10 ms of CPU per invocation**. When the daily limit is exceeded, Cloudflare returns
**error 1027** ("This website has been temporarily rate limited") *if the route is set to
fail closed*.

**Set the route to fail open.** In the dashboard, under the zone's Workers Routes, each
route has a fail-open / fail-closed setting; fail open sends requests straight to the
origin once the limit is hit, so the site stays up unprotected instead of going down.
For a Worker that sits in front of a live site, that is almost always the right trade.

---

## Testing

```sh
npm run typecheck
npm test
npx vitest            # watch mode
bash scripts/smoke.sh # curl examples against a running `wrangler dev`
```

Tests run inside the real Workers runtime via `@cloudflare/vitest-pool-workers`, using the
bindings declared in `wrangler.jsonc`.

> The `compatibilityDate` in `vitest.config.ts` is pinned slightly behind the one in
> `wrangler.jsonc`, because the `workerd` binary bundled with the test pool lags the
> deployed runtime. Bump it when the pool updates.

---

## Layout

```
src/
  index.ts              fetch handler: try/catch, dispatch, logging
  context.ts            per-request context, built once
  logging.ts            structured JSON log lines
  config/
    types.ts            SiteConfig, GlobalConfig, Decision, Env
    defaults.ts         safe baseline for every key
    sites.ts            static per-site entries
    merge.ts            deep merge for KV overrides
    loader.ts           static + KV merge, module-scope cache
  engine/
    pipeline.ts         ordered evaluation, first match wins
    ip.ts               IPv4/IPv6 parsing and CIDR matching
    lists.ts            allow/block lists: ip, cidr, asn, country
    methods.ts          HTTP method rules
    paths.ts            sensitive paths, scanner paths, anomaly checks
    wordpress.ts        WordPress-specific rules
    useragent.ts        user-agent rules
    ratelimit.ts        wrapper around the ratelimits binding
    headers.ts          response security headers
  actions/
    block.ts            403/429 responses, never touching the origin
    challenge.ts        optional Turnstile page + signed clearance cookie
  admin/
    api.ts              /__shield/health and the authenticated admin API
docs/
  cloudflare-setup.md   routes, WAF rules, origin lockdown, WordPress real IP
  config-reference.md   every config key: type, default, effect
scripts/smoke.sh        curl examples against wrangler dev
test/                   vitest
```

## Further reading

- [`docs/cloudflare-setup.md`](docs/cloudflare-setup.md) — the dashboard side: routes, the
  free WAF rules you should use *instead* of Worker rules, mandatory origin lockdown, and
  making WordPress see the real visitor IP.
- [`docs/config-reference.md`](docs/config-reference.md) — every configuration key.
