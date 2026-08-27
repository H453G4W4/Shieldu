/**
 * Config resolution: static entry + KV override -> compiled, cached `ResolvedSite`.
 *
 * Caching strategy: one `Map` in module scope, keyed by hostname, holding the fully
 * compiled config and an expiry timestamp. A Worker isolate serves many requests, so in
 * steady state a request does zero I/O. When the entry expires we do one KV read.
 *
 * Failure strategy: a KV error, a missing binding or malformed JSON all fall back to the
 * static config. The shield must never fail because the config store had a bad minute.
 */

import { defaultGlobalConfig, defaultSiteConfig } from './defaults';
import { deepMerge } from './merge';
import { sites as staticSites } from './sites';
import type { Env, GlobalConfig, SiteConfig } from './types';
import type { CompiledList } from '../engine/lists';
import { compileList, mergeCompiledLists } from '../engine/lists';
import { compileCidrList } from '../engine/ip';
import type { Cidr } from '../engine/ip';

/** A site config with its lists already parsed. This is what the pipeline consumes. */
export interface ResolvedSite {
  config: SiteConfig;
  global: GlobalConfig;
  /** Global allow list + site allow list, merged. */
  allow: CompiledList;
  /** Global block list + site block list, merged. */
  block: CompiledList;
  /** Countries that may enter when `countryMode === "allow"`. */
  countryAllow: Set<string>;
  /** Compiled `wordpress.loginAllowlistIp`. */
  loginAllowIp: Cidr[];
  /** Uppercased `wordpress.loginAllowlistCountry`. */
  loginAllowCountry: Set<string>;
  /** Lowercased extra blocked path prefixes. */
  extraBlockedPrefixes: string[];
  /** Lowercased extra always-allowed paths. */
  extraAllowedPaths: Set<string>;
  /** Lowercased extra blocked user-agent substrings. */
  extraBlockedUserAgents: string[];
}

interface CacheEntry {
  /** null means "this hostname is not configured; forward untouched". */
  site: ResolvedSite | null;
  expiresAt: number;
}

/** hostname -> resolved config. Lives for the life of the isolate. */
const cache = new Map<string, CacheEntry>();

/** Cached global config, refreshed on the same TTL. */
let globalCache: { value: GlobalConfig; expiresAt: number } | null = null;

/** Hostnames we have already logged as unknown, to avoid a log line per request. */
const unknownHostLogged = new Map<string, number>();

/** Index of hostname -> static entry, built once at module load. */
const staticByHost = new Map<string, SiteConfig>();
for (const entry of staticSites) {
  const merged = deepMerge(defaultSiteConfig, entry);
  for (const host of merged.hosts) {
    staticByHost.set(host.toLowerCase(), merged);
  }
}

/** Test seam: clear every cache. Not used in production code. */
export function resetConfigCache(): void {
  cache.clear();
  globalCache = null;
  unknownHostLogged.clear();
}

async function readKvJson(env: Env, key: string): Promise<unknown> {
  const kv = env.SHIELD_CONFIG;
  if (kv === undefined) return undefined;
  try {
    // `type: "json"` lets the runtime parse it; a malformed value throws and is caught.
    return (await kv.get(key, 'json')) ?? undefined;
  } catch {
    return undefined;
  }
}

async function loadGlobal(env: Env, now: number): Promise<GlobalConfig> {
  if (globalCache !== null && globalCache.expiresAt > now) return globalCache.value;

  const override = await readKvJson(env, 'global');
  const value = deepMerge(defaultGlobalConfig, override);
  globalCache = { value, expiresAt: now + value.configTtlSeconds * 1000 };
  return value;
}

function compileSite(config: SiteConfig, global: GlobalConfig): ResolvedSite {
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

/**
 * Resolve the configuration for a hostname.
 *
 * Returns null when the hostname has neither a static entry nor a KV override, which the
 * caller treats as "forward to origin untouched".
 */
export async function loadSite(host: string, env: Env, now: number): Promise<ResolvedSite | null> {
  const key = host.toLowerCase();
  const cached = cache.get(key);
  if (cached !== undefined && cached.expiresAt > now) return cached.site;

  const global = await loadGlobal(env, now);
  const ttlMs = global.configTtlSeconds * 1000;
  const staticEntry = staticByHost.get(key);
  const override = await readKvJson(env, `site:${key}`);

  let site: ResolvedSite | null;
  if (staticEntry === undefined && override === undefined) {
    site = null;
  } else {
    // A KV-only site is legal: it merges over the defaults, which are safe.
    const base = staticEntry ?? { ...defaultSiteConfig, hosts: [key] };
    const merged = deepMerge(base, override);
    site = compileSite(merged, global);
  }

  cache.set(key, { site, expiresAt: now + ttlMs });
  return site;
}

/**
 * True at most once per TTL window per hostname. Used so an unconfigured hostname does
 * not produce a log line on every single request.
 */
export function shouldLogUnknownHost(host: string, now: number, ttlSeconds: number): boolean {
  const until = unknownHostLogged.get(host);
  if (until !== undefined && until > now) return false;
  unknownHostLogged.set(host, now + ttlSeconds * 1000);
  return true;
}

/** Drop a hostname from the cache. Called by the admin API after a write. */
export function invalidateSite(host: string): void {
  cache.delete(host.toLowerCase());
}

/** The static entry for a host, before any KV override. Used by the admin API. */
export function staticSiteFor(host: string): SiteConfig | undefined {
  return staticByHost.get(host.toLowerCase());
}
