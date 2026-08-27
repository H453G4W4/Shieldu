/**
 * Allow/block list matching for IP, CIDR, ASN and country.
 *
 * Lists are compiled once, when a merged site config is built (see `config/loader.ts`),
 * and cached in module scope for the config TTL. Per request this module only does byte
 * comparisons and `Set` lookups, which keeps us well inside the Free plan's 10 ms CPU
 * budget.
 */

import type { Decision, ListConfig } from '../config/types';
import type { Cidr, IpBytes } from './ip';
import { compileCidrList, ipInAnyCidr } from './ip';

/** A pre-parsed allow or block list. */
export interface CompiledList {
  cidrs: Cidr[];
  asns: Set<number>;
  countries: Set<string>;
  /** True when the list has no entries at all; lets the pipeline skip it outright. */
  empty: boolean;
}

export const EMPTY_COMPILED_LIST: CompiledList = {
  cidrs: [],
  asns: new Set(),
  countries: new Set(),
  empty: true,
};

/** Compile a `ListConfig` into fast lookup structures. Invalid entries are dropped. */
export function compileList(list: ListConfig): CompiledList {
  const cidrs = compileCidrList([...list.ip, ...list.cidr]);
  const asns = new Set<number>();
  for (const asn of list.asn) {
    if (Number.isInteger(asn) && asn > 0) asns.add(asn);
  }
  const countries = new Set<string>();
  for (const country of list.country) {
    if (typeof country === 'string' && country.length === 2) {
      countries.add(country.toUpperCase());
    }
  }
  return {
    cidrs,
    asns,
    countries,
    empty: cidrs.length === 0 && asns.size === 0 && countries.size === 0,
  };
}

/** Merge two compiled lists (global + site) without re-parsing. */
export function mergeCompiledLists(a: CompiledList, b: CompiledList): CompiledList {
  if (a.empty) return b;
  if (b.empty) return a;
  const cidrs = [...a.cidrs, ...b.cidrs];
  const asns = new Set([...a.asns, ...b.asns]);
  const countries = new Set([...a.countries, ...b.countries]);
  return {
    cidrs,
    asns,
    countries,
    empty: cidrs.length === 0 && asns.size === 0 && countries.size === 0,
  };
}

/** What was matched, so the log line can say why. */
export type ListMatchKind = 'ip' | 'asn' | 'country';

export interface ListMatch {
  kind: ListMatchKind;
  detail: string;
}

/**
 * Test an IP/ASN/country triple against a compiled list.
 *
 * `country` is matched here only for the block list. Country *allow* mode is a separate
 * rule in the pipeline because its semantics are inverted ("only these may enter").
 */
export function matchList(
  list: CompiledList,
  ip: IpBytes | null,
  asn: number,
  country: string,
  options: { includeCountry: boolean },
): ListMatch | null {
  if (list.empty) return null;
  if (ipInAnyCidr(ip, list.cidrs)) return { kind: 'ip', detail: 'ip' };
  if (asn > 0 && list.asns.has(asn)) return { kind: 'asn', detail: `AS${asn}` };
  if (options.includeCountry && country !== '' && list.countries.has(country)) {
    return { kind: 'country', detail: country };
  }
  return null;
}

/** Convenience: does the allow list cover this client at all? */
export function isAllowListed(
  list: CompiledList,
  ip: IpBytes | null,
  asn: number,
  country: string,
): ListMatch | null {
  return matchList(list, ip, asn, country, { includeCountry: true });
}

/** Build the block Decision for a list match. */
export function blockDecisionForMatch(match: ListMatch): Decision {
  return {
    ruleId: `list.block.${match.kind}`,
    action: 'block',
    status: 403,
    detail: match.detail,
  };
}
