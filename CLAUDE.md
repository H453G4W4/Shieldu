# CLAUDE.md — edge-shield

Guidance for Claude Code (and any other agent) working in this repository.

## 1. Language rules (non-negotiable)

- **Talk to the user in Arabic.** Explanations, plans, questions, summaries and warnings
  are always written in Arabic.
- **Everything inside the repository is in English.** Code, comments, file names,
  identifiers, configuration, documentation, commit messages and log messages.
- Technical terms may stay in English inside Arabic sentences.
- **Never translate code or CLI output.** Paste it verbatim.

## 2. What this project is

`edge-shield` is a single reusable Cloudflare Worker that is attached to several zones
through Worker routes. It sits in front of the origin as a programmable security layer:
IP/CIDR/ASN/country lists, method and path rules, WordPress hardening, user-agent rules,
rate limiting, and response security headers — all driven by per-hostname configuration.

## 3. Hard constraints

- TypeScript with `strict: true`. Configuration lives in `wrangler.jsonc`.
- **Zero runtime npm dependencies.** Dev dependencies only.
- Must run inside the **Workers Free plan CPU budget (10 ms per invocation)**:
  precompile regexes at module load, cache parsed config in module scope, and never make
  a per-request network call other than a memory-cached KV read.
- The client IP comes **only** from the `CF-Connecting-IP` header. Never trust
  `X-Forwarded-For`.
- Geo/ASN data comes from `request.cf` (`country`, `asn`, `asOrganization`, `isEUCountry`).
  `request.cf` may be missing in local dev — treat it as unknown, never crash.
- **Fail open by default.** If the Worker throws, forward the request to the origin
  unchanged. `failClosed: true` is a per-site opt-in. The whole handler is wrapped in
  try/catch.
- **Never break** `/wp-admin/admin-ajax.php`, `/wp-admin/admin-post.php`, `/wp-json/` for
  logged-in users, `wp-cron.php` when external cron is enabled, or xmlrpc when
  Jetpack/WooCommerce needs it. Each is behind a per-site flag with a safe default.
- Never block well-known search-engine crawlers with user-agent rules.
- **No secrets in files.** Secrets are set with `wrangler secret put`.
- **Do not buffer response bodies.** Stream them through when adding headers.

## 4. Working rules

- Small, focused files. No clever abstractions.
- Comment the **why** on anything WordPress-specific.
- Every rule has a stable string `id` so logs say exactly which rule fired.
- If any Cloudflare API, binding, limit or configuration key is uncertain, check
  `developers.cloudflare.com` instead of guessing, and tell the user in Arabic what was
  verified.
- After each phase: typecheck and tests pass -> commit (Conventional Commits, English)
  -> short Arabic summary of what was done and what comes next.
- **Never run `wrangler deploy`** and never write secrets to files without explicit
  confirmation from the user.

## 5. Commands

```sh
npm install
npm run typecheck     # tsc --noEmit
npm test              # vitest run
npm run dev           # wrangler dev
npm run deploy        # DO NOT run this on the user's behalf
```

## 6. Decision pipeline order

Documented in `README.md`. Keep the code, the README and `docs/config-reference.md` in
sync whenever a rule is added, removed or renamed.
