#!/usr/bin/env bash
#
# Smoke tests for edge-shield against a running `wrangler dev`.
#
#   Terminal 1:  npm run dev
#   Terminal 2:  bash scripts/smoke.sh
#
# Every request sets a Host header so the Worker resolves a site config, and a
# CF-Connecting-IP header so the IP rules have something to match. `wrangler dev` does not
# populate request.cf the way the edge does, so geo rules will not fire locally -- that is
# expected, and the Worker treats unknown geo data as "no match".
#
# The script only reports what it sees; it does not assert. Read the output.

set -uo pipefail

BASE="${BASE:-http://127.0.0.1:8787}"
HOST="${HOST:-example.com}"
CLIENT_IP="${CLIENT_IP:-198.51.100.77}"
ADMIN_TOKEN="${SHIELD_ADMIN_TOKEN:-}"

bold() { printf '\033[1m%s\033[0m\n' "$1"; }
dim() { printf '\033[2m%s\033[0m\n' "$1"; }

# probe <label> <expected-status-hint> [extra curl args...]
probe() {
  local label="$1" hint="$2"
  shift 2
  local status
  status=$(curl -s -o /dev/null -w '%{http_code}' \
    -H "Host: ${HOST}" \
    -H "CF-Connecting-IP: ${CLIENT_IP}" \
    "$@" 2>/dev/null)
  printf '  %-52s %s   %s\n' "$label" "$status" "$(dim "expect ${hint}")"
}

bold "edge-shield smoke test"
dim  "base=${BASE}  host=${HOST}  client-ip=${CLIENT_IP}"
echo
dim  "Sites ship in mode: \"monitor\", so blocking rules LOG but still return 200."
dim  "Switch the site to \"enforce\" (see below) to see real 403s."
echo

bold "1. Shield endpoints"
probe "GET  /__shield/health" "200" "${BASE}/__shield/health"
probe "POST /__shield/health" "405" -X POST "${BASE}/__shield/health"
probe "GET  /__shield/api/config (no token)" "401" "${BASE}/__shield/api/config?host=${HOST}"
echo

bold "2. Ordinary traffic (should always pass)"
probe "GET  /" "200 or origin error" "${BASE}/"
probe "GET  /robots.txt" "200 or origin error" "${BASE}/robots.txt"
probe "GET  /wp-content/uploads/2026/01/photo.jpg" "pass" "${BASE}/wp-content/uploads/2026/01/photo.jpg"
echo

bold "3. WordPress endpoints that MUST NEVER break"
probe "POST /wp-admin/admin-ajax.php" "pass" -X POST "${BASE}/wp-admin/admin-ajax.php"
probe "POST /wp-admin/admin-post.php" "pass" -X POST "${BASE}/wp-admin/admin-post.php"
probe "GET  /wp-json/wp/v2/posts" "pass" "${BASE}/wp-json/wp/v2/posts"
probe "GET  /wp-json/wp/v2/users (logged in)" "pass" \
  -H 'Cookie: wordpress_logged_in_abc=admin|1|x' "${BASE}/wp-json/wp/v2/users"
echo

bold "4. WordPress rules (403 in enforce mode)"
probe "GET  /xmlrpc.php" "403" "${BASE}/xmlrpc.php"
probe "GET  /wp-config.php" "403" "${BASE}/wp-config.php"
probe "GET  /readme.html" "403" "${BASE}/readme.html"
probe "GET  /wp-cron.php" "403" "${BASE}/wp-cron.php"
probe "GET  /wp-admin/install.php" "403" "${BASE}/wp-admin/install.php"
probe "GET  /wp-content/uploads/shell.php" "403" "${BASE}/wp-content/uploads/shell.php"
probe "GET  /wp-includes/wlwmanifest.xml.php" "403" "${BASE}/wp-includes/wlwmanifest.xml.php"
probe "GET  /?author=1 (user enumeration)" "403" "${BASE}/?author=1"
probe "GET  /wp-json/wp/v2/users (logged out)" "403" "${BASE}/wp-json/wp/v2/users"
echo

bold "5. Generic scanner paths (403 in enforce mode)"
probe "GET  /.env" "403" "${BASE}/.env"
probe "GET  /.git/config" "403" "${BASE}/.git/config"
probe "GET  /phpmyadmin/index.php" "403" "${BASE}/phpmyadmin/index.php"
probe "GET  /vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php" "403" \
  "${BASE}/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php"
probe "GET  /backup.sql" "403" "${BASE}/backup.sql"
probe "GET  /%2egit/config (encoded)" "403" "${BASE}/%2egit/config"
echo

bold "6. Anomalies (403/400/414 in enforce mode)"
probe "GET  /file%00.jpg (null byte)" "400" "${BASE}/file%00.jpg"
probe "GET  /x/%2e%2e%2fetc/passwd (traversal)" "400" "${BASE}/x/%2e%2e%2fetc/passwd"
probe "GET  /?id=1+UNION+SELECT+x+FROM+y" "403" "${BASE}/?id=1+UNION+SELECT+x+FROM+y"
probe "GET  /s?q=%3Cscript%3Ealert(1)" "403" "${BASE}/s?q=%3Cscript%3Ealert(1)"
echo

bold "7. User agents"
probe "GET  / as sqlmap" "403" -A 'sqlmap/1.7.2#stable' "${BASE}/"
probe "GET  / as wpscan" "403" -A 'WPScan v3.8.22' "${BASE}/"
probe "GET  / as Googlebot" "pass (never blocked)" \
  -A 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)' "${BASE}/"
probe "GET  / as curl" "pass (off by default)" -A 'curl/8.4.0' "${BASE}/"
echo

bold "8. Methods"
probe "TRACE /" "405" -X TRACE "${BASE}/"
echo

bold "9. Allow list precedence"
dim  "203.0.113.10 is in the static allow list for example.com."
probe "GET  /.env from an allow-listed IP" "pass" \
  -H 'CF-Connecting-IP: 203.0.113.10' "${BASE}/.env"
echo

if [ -n "${ADMIN_TOKEN}" ]; then
  bold "10. Admin API"
  probe "GET  /__shield/api/config" "200" \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" "${BASE}/__shield/api/config?host=${HOST}"
  probe "GET  /__shield/api/config (bad token)" "401" \
    -H "Authorization: Bearer wrong" "${BASE}/__shield/api/config?host=${HOST}"
  echo
  dim "Effective config:"
  curl -s -H "Host: ${HOST}" -H "Authorization: Bearer ${ADMIN_TOKEN}" \
    "${BASE}/__shield/api/config?host=${HOST}" | head -c 600
  echo
else
  bold "10. Admin API (skipped)"
  dim  "Set SHIELD_ADMIN_TOKEN in .dev.vars and export it here to exercise the admin API."
fi

echo
bold "Switching example.com to enforce for a real test"
cat <<'EOF'
  # 1. Put SHIELD_ADMIN_TOKEN in .dev.vars, restart `wrangler dev`, then:
  export SHIELD_ADMIN_TOKEN=...
  curl -sX POST http://127.0.0.1:8787/__shield/api/mode \
    -H "Host: example.com" \
    -H "Authorization: Bearer $SHIELD_ADMIN_TOKEN" \
    -H 'Content-Type: application/json' \
    -d '{"host":"example.com","mode":"enforce"}'

  # 2. Re-run this script. The 403s should now be real.
  # 3. Switch back:
  curl -sX DELETE "http://127.0.0.1:8787/__shield/api/override?host=example.com" \
    -H "Host: example.com" -H "Authorization: Bearer $SHIELD_ADMIN_TOKEN"
EOF
