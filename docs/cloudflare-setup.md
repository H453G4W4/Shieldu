# Cloudflare setup

Everything that happens in the Cloudflare dashboard rather than in this repository.

Read section 3 first. Without origin lockdown, this Worker is decoration.

---

## 1. Worker routes

The Worker only runs on hostnames you attach it to.

**Prerequisites for every zone:**

- The zone is in the **same Cloudflare account** as the Worker. A Worker cannot be routed
  to a zone in another account.
- The DNS record for the hostname is **proxied** — the orange cloud. A grey-cloud
  (DNS-only) record bypasses Cloudflare's network entirely, so no Worker runs.

**In `wrangler.jsonc`:**

```jsonc
"routes": [
  { "pattern": "example.com/*",     "zone_name": "example.com" },
  { "pattern": "www.example.com/*", "zone_name": "example.com" },
  { "pattern": "shop.example.org/*","zone_name": "example.org" }
]
```

One entry per hostname you want covered. `zone_name` is the zone the hostname belongs to,
not the hostname itself.

**Or in the dashboard:** *Zone → Workers Routes → Add route*, pattern `example.com/*`,
service `edge-shield`.

**Fail-open setting.** Each route has a fail-open / fail-closed option. Set it to
**fail open** so that when the Free plan's daily request limit is hit, requests go
straight to the origin instead of returning Cloudflare error 1027. For a Worker in front
of a live site, staying up unprotected beats going down. (See "Free plan limits" in the
README.)

**Order of operations.** Attaching a route to a hostname with no config entry is safe:
`edge-shield` forwards unknown hostnames to the origin untouched, and logs the hostname
once per config TTL window. So you can attach the route first and add the config after.

---

## 2. Do these in Cloudflare, not in the Worker

**Cloudflare's WAF runs before Workers.** A request blocked by a WAF rule never reaches
the Worker, never consumes a Worker request from the daily quota, and never costs CPU. For
anything static — a country, an ASN, a fixed IP range, a single path — the WAF is strictly
better. Use the Worker for what the WAF cannot express: per-hostname configuration,
dynamic lists you change through an API, WordPress-aware logic, and monitor mode.

### Free plan allowances

| Feature | Free plan |
| --- | --- |
| WAF custom rules | **5 rules**, no regular expressions, no `Log` action |
| Rate limiting rules | **1 rule** |
| Cloudflare Free Managed Ruleset | included, on by default |
| IP Access Rules | unlimited, and they do not count against the 5 custom rules |
| Bot Fight Mode | included |
| Under Attack mode | included |

> Because `Log` is not available on the Free plan, a custom rule cannot be run in
> "monitor" mode. That is precisely what `edge-shield`'s `mode: "monitor"` is for: work out
> what you want to block in the Worker's logs first, then promote the stable rules into
> WAF custom rules and free the Worker up for the dynamic ones.

### Turn these on first

- **WAF → Managed rules → Cloudflare Free Managed Ruleset** — on by default; confirm it is
  enabled.
- **Security → Bots → Bot Fight Mode** — free, catches a large share of automated traffic
  before the Worker sees it.
- **SSL/TLS → Overview → Full (strict)** — anything less lets an attacker MITM the
  Cloudflare-to-origin leg.
- **SSL/TLS → Edge Certificates → Always Use HTTPS** — on.
- **Security → Settings → Security Level** — `Medium` is a good default. `I'm Under Attack`
  is the emergency switch during an active attack; it interstitials every visitor, so it is
  not a steady state.

### IP Access Rules (unlimited, free)

*Security → WAF → Tools*. Use these for permanent, coarse decisions — they are free,
unlimited, and evaluated before custom rules:

- Block an abusive IP or `/24`.
- Block an ASN outright (`Autonomous System Number`, e.g. `AS14061`).
- Block a country outright.
- **Allow** your own office/VPN address, so nothing else can ever lock you out.

### WAF custom rules — ready to paste

*Security → WAF → Custom rules → Create rule*, then "Edit expression" and paste. You have
five; spend them on the highest-volume, most static rules.

**1. Block hosting-provider ASNs from ever reaching the login page**

```
(http.request.uri.path contains "/wp-login.php" and ip.geoip.asnum in {14061 16509 14618 16276 24940 20473 63949 51167 45102})
```
Action: **Block**.
Those are DigitalOcean, AWS, AWS, OVH, Hetzner, Vultr, Linode, Alibaba and Contabo — real
visitors do not log in to a blog from a datacentre. Adjust the list to taste.

**2. Country allow-list for the admin area**

```
(starts_with(http.request.uri.path, "/wp-admin/") and not ip.geoip.country in {"MA" "FR"})
and not http.request.uri.path in {"/wp-admin/admin-ajax.php" "/wp-admin/admin-post.php"}
```
Action: **Block**.
Replace `MA` and `FR` with the countries you actually administer from. **Keep the
`admin-ajax.php` / `admin-post.php` exclusion** — logged-out visitors use both.

**3. Block xmlrpc outright**

```
(http.request.uri.path eq "/xmlrpc.php")
```
Action: **Block**. Skip this rule if you use Jetpack or the WordPress mobile app.

**4. Block obvious scanner paths**

```
(http.request.uri.path in {"/.env" "/.git/config" "/wp-config.php" "/.htaccess" "/phpinfo.php" "/config.json"})
or (starts_with(http.request.uri.path, "/vendor/phpunit"))
or (starts_with(http.request.uri.path, "/.git/"))
```
Action: **Block**.

**5. Block known scanner user agents**

```
(any(lower(http.request.headers["user-agent"][*]) contains "sqlmap"))
or (any(lower(http.request.headers["user-agent"][*]) contains "nikto"))
or (any(lower(http.request.headers["user-agent"][*]) contains "wpscan"))
or (any(lower(http.request.headers["user-agent"][*]) contains "nuclei"))
```
Action: **Block**. Free-plan custom rules do not support regular expressions, hence the
`contains` chain.

### Rate limiting rule (1 free rule)

*Security → WAF → Rate limiting rules*. Spend the single free rule on the login page,
which is the highest-value target:

- **Expression:** `(http.request.uri.path eq "/wp-login.php" and http.request.method eq "POST")`
- **Characteristics:** IP
- **Rate:** 5 requests per 10 seconds (or per 60 seconds for a stricter limit)
- **Action:** Block, duration 10 minutes

`edge-shield`'s own `login` rate limit then covers the second layer, and gives you the
same protection for `xmlrpc` and comments, which the single free WAF rule cannot.

---

## 3. Origin lockdown — mandatory

**Everything above is bypassable by anyone who can reach your origin IP directly.** A
Worker only runs on traffic that goes through Cloudflare. If an attacker resolves your
server's real address, they talk to the origin and none of this applies.

Pick **one** of the three. Cloudflare Tunnel is the strongest; the firewall allow list is
the most common.

### Option A — allow only Cloudflare IPs at the origin firewall

Cloudflare publishes its ranges at <https://www.cloudflare.com/ips/> (machine-readable at
`https://www.cloudflare.com/ips-v4` and `https://www.cloudflare.com/ips-v6`). Allow
`80/443` from those ranges and deny everything else.

```sh
# Example, ufw. Re-run when Cloudflare updates its ranges (rare, but it happens).
for ip in $(curl -s https://www.cloudflare.com/ips-v4) $(curl -s https://www.cloudflare.com/ips-v6); do
  ufw allow from "$ip" to any port 443 proto tcp
  ufw allow from "$ip" to any port 80 proto tcp
done
ufw deny 80/tcp
ufw deny 443/tcp
```

On shared hosting without a firewall, the `.htaccess` equivalent works but is weaker
(Apache still accepts the connection):

```apache
# Requires mod_remoteip configured with Cloudflare's ranges, or it will lock you out.
<RequireAll>
  Require ip 173.245.48.0/20 103.21.244.0/22 103.22.200.0/22 ...
</RequireAll>
```

Better: ask the host to enable **Authenticated Origin Pulls** instead.

### Option B — Authenticated Origin Pulls (mTLS)

*Zone → SSL/TLS → Origin Server → Authenticated Origin Pulls*. Cloudflare presents a
client certificate on every origin request; the origin rejects connections without it.
This survives an IP leak, because knowing the address is no longer enough.

Nginx:

```nginx
ssl_client_certificate /etc/nginx/certs/cloudflare-origin-pull-ca.pem;
ssl_verify_client on;
```

### Option C — Cloudflare Tunnel (`cloudflared`)

The origin makes an **outbound** connection to Cloudflare and needs **no inbound ports open
at all**. There is no origin IP to leak. This is the strongest option and it is free.

```sh
cloudflared tunnel login
cloudflared tunnel create my-site
cloudflared tunnel route dns my-site example.com
cloudflared tunnel run my-site
```

### Common ways an origin IP leaks

Even with a proxied `A` record, the real address commonly escapes through:

- **MX records.** Mail usually points at the same server, and MX records cannot be proxied.
  Host mail elsewhere, or on a different IP.
- **Unproxied subdomains.** `ftp.`, `cpanel.`, `direct.`, `mail.`, `webmail.`, `dev.`,
  `staging.` — anything grey-clouded. Audit every record in the DNS tab.
- **DNS history.** Services like SecurityTrails and ViewDNS keep records from before you
  moved to Cloudflare. If the address is already public, **change the origin IP** — that is
  the only real fix.
- **Email headers.** Mail sent from the server (WordPress notifications, contact forms)
  carries the origin IP in `Received:` headers. Send through an SMTP relay instead.
- **Outbound requests.** Webhooks, cron jobs and `wp_remote_get` calls reveal the address
  to whoever receives them.
- **TLS certificates.** Certificate Transparency logs expose subdomains you never
  advertised. Check <https://crt.sh> for your domain.
- **Origin error pages.** A default nginx/Apache page or a PHP error can print the server
  hostname or IP.

**Verify the lockdown:**

```sh
# Should time out or be refused, not return your site.
curl -sv --max-time 10 --resolve example.com:443:<ORIGIN_IP> https://example.com/
```

---

## 4. WordPress: see the real visitor IP

Behind Cloudflare, `$_SERVER['REMOTE_ADDR']` is a **Cloudflare** address. Until you fix
this, WordPress logs, comment moderation, Limit Login Attempts, Wordfence and every other
security plugin will see one IP for the whole internet — and will happily ban Cloudflare.

**Option A — the official plugin.** Install *Cloudflare* by Cloudflare, Inc. It restores
the visitor IP among other things.

**Option B — an mu-plugin.** Create `wp-content/mu-plugins/cloudflare-real-ip.php`. This
is a two-line change with a real security consequence, so it is written defensively:

```php
<?php
/**
 * Plugin Name: Cloudflare real visitor IP
 * Description: Restores the visitor IP from CF-Connecting-IP.
 *
 * SAFETY: only trust the header when the connection actually comes from a Cloudflare
 * range. Without that check, anyone can spoof CF-Connecting-IP and defeat every IP-based
 * ban on the site.
 */

if ( ! empty( $_SERVER['HTTP_CF_CONNECTING_IP'] ) ) {
	$cf_ranges = array(
		// IPv4 -- refresh from https://www.cloudflare.com/ips-v4
		'173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22',
		'141.101.64.0/18', '108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20',
		'197.234.240.0/22', '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13',
		'104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22',
		// IPv6 -- refresh from https://www.cloudflare.com/ips-v6
		'2400:cb00::/32', '2606:4700::/32', '2803:f800::/32', '2405:b500::/32',
		'2405:8100::/32', '2a06:98c0::/29', '2c0f:f248::/32',
	);

	$remote = $_SERVER['REMOTE_ADDR'];
	$trusted = false;

	foreach ( $cf_ranges as $range ) {
		list( $subnet, $bits ) = explode( '/', $range );
		$ip_bin     = @inet_pton( $remote );
		$subnet_bin = @inet_pton( $subnet );
		if ( false === $ip_bin || false === $subnet_bin ) {
			continue;
		}
		if ( strlen( $ip_bin ) !== strlen( $subnet_bin ) ) {
			continue; // different address family
		}

		$bytes = intdiv( (int) $bits, 8 );
		$rest  = (int) $bits % 8;
		if ( $bytes > 0 && substr( $ip_bin, 0, $bytes ) !== substr( $subnet_bin, 0, $bytes ) ) {
			continue;
		}
		if ( $rest > 0 ) {
			$mask = chr( 0xff << ( 8 - $rest ) & 0xff );
			if ( ( $ip_bin[ $bytes ] & $mask ) !== ( $subnet_bin[ $bytes ] & $mask ) ) {
				continue;
			}
		}
		$trusted = true;
		break;
	}

	if ( $trusted && filter_var( $_SERVER['HTTP_CF_CONNECTING_IP'], FILTER_VALIDATE_IP ) ) {
		$_SERVER['REMOTE_ADDR'] = $_SERVER['HTTP_CF_CONNECTING_IP'];
	}
}
```

Cloudflare also sends `CF-IPCountry` (visitor country) and `CF-Ray` (request id) — both
useful in origin logs.

**Verify:** publish a comment or check *Users → your profile → session*, and confirm the
recorded IP is yours, not `172.x` / `104.x`.

---

## 5. HSTS: dashboard or Worker?

Both work. Pick one; do not do both.

| | Dashboard (*SSL/TLS → Edge Certificates → HSTS*) | Worker (`headers.hsts`) |
| --- | --- | --- |
| Scope | the whole zone | per hostname |
| Applies to | every response, including Cloudflare error pages | origin responses only |
| Cost | free, no CPU | a header write per request |
| Best for | one policy for the entire zone | different policies per hostname, or a staged rollout |

**Prefer the dashboard** when every hostname in the zone should have the same policy —
it also covers responses the Worker never sees. **Prefer the Worker** when hostnames in
one zone need different policies, or when you want to raise `max-age` gradually.

**Before enabling either:**

1. Every hostname, including every subdomain, must serve HTTPS correctly.
2. Start with a short `max-age` (e.g. `300`) and raise it once you are confident.
3. Only add `includeSubDomains` after auditing every subdomain — it will break any
   HTTP-only one, and browsers cache the instruction for `max-age` seconds regardless of
   what you do afterwards.
4. Only add `preload` if you genuinely intend to submit to the preload list. Getting off
   that list takes months.

---

## 6. Rollout checklist

- [ ] Zone is proxied (orange cloud) and in the same account as the Worker
- [ ] Origin locked down (firewall allow list, mTLS, or Tunnel) — **verified with curl**
- [ ] No unproxied subdomain, MX record or DNS-history entry leaks the origin IP
- [ ] SSL/TLS mode is Full (strict), Always Use HTTPS on
- [ ] Free Managed Ruleset on, Bot Fight Mode on
- [ ] IP Access Rule allowing your own address
- [ ] WAF custom rules for the static, high-volume blocks
- [ ] Free rate limiting rule on `POST /wp-login.php`
- [ ] WordPress sees the real visitor IP
- [ ] `SHIELD_ADMIN_TOKEN` set with `wrangler secret put`
- [ ] KV namespace created and its id in `wrangler.jsonc`
- [ ] Your own IP in the site's `allow.ip`
- [ ] Worker route added, set to **fail open**
- [ ] Site deployed in `mode: "monitor"`
- [ ] Logs reviewed for a few days: `npx wrangler tail --format=json | grep '"monitored":true'`
- [ ] Switched to `mode: "enforce"`
