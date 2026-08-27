/**
 * User-agent rules.
 *
 * IMPORTANT: the User-Agent header is attacker-controlled and trivially spoofed. These
 * rules exist to cut obvious scanner noise out of the logs, not to stop a determined
 * attacker. Nothing else in the shield depends on them.
 *
 * The good-bot allow list is checked first and is on by default, so a UA rule can never
 * de-index a site. It is also best effort: anyone can claim to be Googlebot. Verifying a
 * crawler properly needs a reverse DNS lookup, which a Worker cannot do — use
 * Cloudflare's "Verified Bots" signal in a WAF rule if you need certainty.
 */

import type { RequestContext } from '../context';
import type { Decision } from '../config/types';

/** Lowercase substrings identifying well-known crawlers we must never block. */
export const GOOD_BOT_UA_SUBSTRINGS: readonly string[] = [
  'googlebot',
  'google-inspectiontool',
  'storebot-google',
  'bingbot',
  'bingpreview',
  'slurp', // Yahoo
  'duckduckbot',
  'baiduspider',
  'yandexbot',
  'applebot',
  'facebookexternalhit',
  'twitterbot',
  'linkedinbot',
  'pinterestbot',
  'slackbot',
  'telegrambot',
  'whatsapp',
  'discordbot',
  'redditbot',
  'petalbot',
  'seznambot',
  'ia_archiver',
  'archive.org_bot',
  'uptimerobot',
  'pingdom',
  'chrome-lighthouse',
  'google page speed',
  'ahrefsbot',
  'semrushbot',
];

/** Offensive-security tooling. Blocked by default. */
export const SCANNER_UA_SUBSTRINGS: readonly string[] = [
  'sqlmap',
  'nikto',
  'masscan',
  'nmap',
  'zgrab',
  'dirbuster',
  'gobuster',
  'feroxbuster',
  'wpscan',
  'nuclei',
  'acunetix',
  'netsparker',
  'arachni',
  'metasploit',
  'havij',
  'jaeles',
  'xsstrike',
  'commix',
  'joomscan',
  'whatweb',
  'wfuzz',
  'fuzz faster u fool', // ffuf
];

/** Generic HTTP clients. Legitimate for APIs, so this is opt-in per site. */
export const GENERIC_CLIENT_UA_SUBSTRINGS: readonly string[] = [
  'python-requests',
  'python-urllib',
  'aiohttp',
  'go-http-client',
  'java/',
  'okhttp',
  'libwww-perl',
  'winhttp',
  'curl/',
  'wget/',
  'httpie',
  'postmanruntime',
];

function containsAny(haystack: string, needles: readonly string[]): string | null {
  for (let i = 0; i < needles.length; i++) {
    const needle = needles[i] as string;
    if (haystack.indexOf(needle) !== -1) return needle;
  }
  return null;
}

/** True when the UA claims to be a well-known crawler. Best effort; UA can be spoofed. */
export function isGoodBot(uaLower: string): boolean {
  return containsAny(uaLower, GOOD_BOT_UA_SUBSTRINGS) !== null;
}

export function evaluateUserAgent(ctx: RequestContext): Decision | null {
  const rules = ctx.site.config.userAgents;
  const ua = ctx.uaLower;

  if (rules.allowGoodBots && ua !== '' && isGoodBot(ua)) return null;

  if (ua === '') {
    if (rules.blockEmpty) {
      return { ruleId: 'ua.empty', action: 'block', status: 403 };
    }
    return null;
  }

  const extra = containsAny(ua, ctx.site.extraBlockedUserAgents);
  if (extra !== null) {
    return { ruleId: 'ua.extraBlocked', action: 'block', status: 403, detail: extra };
  }

  if (rules.blockKnownScanners) {
    const scanner = containsAny(ua, SCANNER_UA_SUBSTRINGS);
    if (scanner !== null) {
      return { ruleId: 'ua.scanner', action: 'block', status: 403, detail: scanner };
    }
  }

  if (rules.blockGenericClients) {
    const client = containsAny(ua, GENERIC_CLIENT_UA_SUBSTRINGS);
    if (client !== null) {
      return { ruleId: 'ua.genericClient', action: 'block', status: 403, detail: client };
    }
  }

  return null;
}
