/**
 * Test helpers: build a `ResolvedSite` and a `RequestContext` without going through KV.
 */

import { defaultGlobalConfig, defaultSiteConfig } from '../src/config/defaults';
import { deepMerge } from '../src/config/merge';
import type { DeepPartial, Env, SiteConfig } from '../src/config/types';
import type { ResolvedSite } from '../src/config/loader';
import { buildContext } from '../src/context';
import type { RequestContext } from '../src/context';
import { compileCidrList } from '../src/engine/ip';
import { compileList, mergeCompiledLists } from '../src/engine/lists';

export function makeSite(overrides: DeepPartial<SiteConfig> = {}): ResolvedSite {
  const config = deepMerge(defaultSiteConfig, overrides);
  const global = defaultGlobalConfig;
  return {
    config,
    global,
    allow: mergeCompiledLists(compileList(global.allow), compileList(config.allow)),
    block: mergeCompiledLists(compileList(global.block), compileList(config.block)),
    countryAllow: new Set(config.allow.country.map((c) => c.toUpperCase())),
    loginAllowIp: compileCidrList(config.wordpress.loginAllowlistIp),
    loginAllowCountry: new Set(config.wordpress.loginAllowlistCountry.map((c) => c.toUpperCase())),
    extraBlockedPrefixes: config.paths.extraBlockedPrefixes.map((p) => p.toLowerCase()),
    extraAllowedPaths: new Set(config.paths.extraAllowedPaths.map((p) => p.toLowerCase())),
    extraBlockedUserAgents: config.userAgents.extraBlocked.map((u) => u.toLowerCase()),
  };
}

export interface MakeRequestOptions {
  url?: string;
  method?: string;
  ip?: string;
  country?: string;
  asn?: number;
  asOrg?: string;
  ua?: string;
  headers?: Record<string, string>;
  cookie?: string;
  /** Omit `cf` entirely, as happens in local dev. */
  noCf?: boolean;
}

export function makeRequest(options: MakeRequestOptions = {}): Request {
  const url = options.url ?? 'https://example.com/';
  const headers = new Headers(options.headers ?? {});
  if (options.ip !== undefined) headers.set('CF-Connecting-IP', options.ip);
  if (options.ua !== undefined) headers.set('User-Agent', options.ua);
  if (options.cookie !== undefined) headers.set('Cookie', options.cookie);

  const init: RequestInit = { method: options.method ?? 'GET', headers };
  if (!options.noCf) {
    (init as RequestInit & { cf?: unknown }).cf = {
      country: options.country ?? 'US',
      asn: options.asn ?? 64500,
      asOrganization: options.asOrg ?? 'Example ISP',
      isEUCountry: '0',
    };
  }
  return new Request(url, init);
}

export function makeContext(
  site: ResolvedSite,
  options: MakeRequestOptions = {},
): RequestContext {
  const request = makeRequest(options);
  return buildContext(request, new URL(request.url), site);
}

/** An `Env` with no bindings at all, to exercise the fail-open paths. */
export const emptyEnv: Env = {};
