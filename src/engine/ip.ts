/**
 * Dependency-free IPv4/IPv6 parsing and CIDR matching.
 *
 * Every address is normalised to 16 bytes. IPv4 addresses are stored as IPv4-mapped IPv6
 * (`::ffff:a.b.c.d`) so that a single comparison path covers both families and so that a
 * client arriving as `::ffff:203.0.113.10` still matches the CIDR `203.0.113.0/24`.
 *
 * Parsing is strict and total: any malformed input returns `null` instead of throwing.
 * Nothing in this module allocates beyond the 16-byte result, and CIDR lists are compiled
 * once at config-merge time (see `lists.ts`) so the per-request cost is a byte compare.
 */

/** A parsed address: always 16 bytes, IPv4 stored as IPv4-mapped IPv6. */
export type IpBytes = Uint8Array;

/** A parsed CIDR block. `prefix` is expressed in the 128-bit space (IPv4 /24 -> 120). */
export interface Cidr {
  base: IpBytes;
  prefix: number;
  /** The original text, kept for logging and for the admin API round-trip. */
  source: string;
}

const IPV4_MAPPED_PREFIX_LENGTH = 96;

function parseIpv4(text: string): Uint8Array | null {
  const parts = text.split('.');
  if (parts.length !== 4) return null;
  const out = new Uint8Array(4);
  for (let i = 0; i < 4; i++) {
    const part = parts[i];
    if (part === undefined || part.length === 0 || part.length > 3) return null;
    // Reject leading zeros: "010" is ambiguous (octal in some parsers) and a classic
    // way to smuggle an address past a naive allow list.
    if (part.length > 1 && part.charCodeAt(0) === 48) return null;
    let value = 0;
    for (let j = 0; j < part.length; j++) {
      const code = part.charCodeAt(j);
      if (code < 48 || code > 57) return null;
      value = value * 10 + (code - 48);
    }
    if (value > 255) return null;
    out[i] = value;
  }
  return out;
}

function parseHexGroup(group: string): number | null {
  if (group.length === 0 || group.length > 4) return null;
  let value = 0;
  for (let i = 0; i < group.length; i++) {
    const code = group.charCodeAt(i);
    let digit: number;
    if (code >= 48 && code <= 57) digit = code - 48;
    else if (code >= 97 && code <= 102) digit = code - 87;
    else if (code >= 65 && code <= 70) digit = code - 55;
    else return null;
    value = value * 16 + digit;
  }
  return value;
}

/**
 * Expand a trailing dotted-quad group ("::ffff:1.2.3.4") into two hex groups.
 * Returns the input unchanged when there is no embedded IPv4, or null when the embedded
 * IPv4 is malformed.
 */
function expandEmbeddedIpv4(groups: string[]): string[] | null {
  const last = groups[groups.length - 1];
  if (last === undefined || last.indexOf('.') === -1) return groups;
  const v4 = parseIpv4(last);
  if (v4 === null) return null;
  const high = ((v4[0] as number) << 8) | (v4[1] as number);
  const low = ((v4[2] as number) << 8) | (v4[3] as number);
  return groups.slice(0, -1).concat([high.toString(16), low.toString(16)]);
}

function parseIpv6(text: string): Uint8Array | null {
  const doubleColon = text.indexOf('::');
  let headText: string;
  let tailText: string;
  const compressed = doubleColon !== -1;
  if (compressed) {
    // Only one "::" is legal.
    if (text.indexOf('::', doubleColon + 1) !== -1) return null;
    headText = text.slice(0, doubleColon);
    tailText = text.slice(doubleColon + 2);
  } else {
    headText = text;
    tailText = '';
  }

  let head = headText === '' ? [] : headText.split(':');
  let tail = tailText === '' ? [] : tailText.split(':');

  // An embedded IPv4 can only ever be the very last group of the whole address.
  if (compressed && tail.length > 0) {
    const expanded = expandEmbeddedIpv4(tail);
    if (expanded === null) return null;
    tail = expanded;
  } else if (head.length > 0) {
    const expanded = expandEmbeddedIpv4(head);
    if (expanded === null) return null;
    head = expanded;
  }

  const total = head.length + tail.length;
  if (compressed) {
    // "::" must stand for at least one zero group.
    if (total > 7) return null;
  } else if (total !== 8) {
    return null;
  }

  const bytes = new Uint8Array(16);
  for (let i = 0; i < head.length; i++) {
    const value = parseHexGroup(head[i] as string);
    if (value === null) return null;
    bytes[i * 2] = value >>> 8;
    bytes[i * 2 + 1] = value & 0xff;
  }
  const offset = 16 - tail.length * 2;
  for (let i = 0; i < tail.length; i++) {
    const value = parseHexGroup(tail[i] as string);
    if (value === null) return null;
    bytes[offset + i * 2] = value >>> 8;
    bytes[offset + i * 2 + 1] = value & 0xff;
  }
  return bytes;
}

/**
 * Parse an IPv4 or IPv6 address into 16 bytes. Accepts bracketed IPv6 (`[::1]`) and
 * strips an RFC 4007 zone id (`fe80::1%eth0`). Returns null for anything malformed.
 */
export function parseIp(input: string): IpBytes | null {
  let text = input.trim();
  if (text.length === 0 || text.length > 64) return null;

  if (text.charCodeAt(0) === 91 /* [ */) {
    if (text.charCodeAt(text.length - 1) !== 93 /* ] */) return null;
    text = text.slice(1, -1);
  }

  const zone = text.indexOf('%');
  if (zone !== -1) text = text.slice(0, zone);
  if (text.length === 0) return null;

  if (text.indexOf(':') === -1) {
    const v4 = parseIpv4(text);
    if (v4 === null) return null;
    return ipv4ToMapped(v4);
  }
  return parseIpv6(text);
}

function ipv4ToMapped(v4: Uint8Array): Uint8Array {
  const bytes = new Uint8Array(16);
  bytes[10] = 0xff;
  bytes[11] = 0xff;
  bytes[12] = v4[0] as number;
  bytes[13] = v4[1] as number;
  bytes[14] = v4[2] as number;
  bytes[15] = v4[3] as number;
  return bytes;
}

/**
 * Parse a CIDR block, or a bare address (treated as a single-host /32 or /128).
 * IPv4 prefixes are shifted into the IPv4-mapped range, so `10.0.0.0/8` becomes /104.
 */
export function parseCidr(input: string): Cidr | null {
  const text = input.trim();
  if (text.length === 0) return null;

  const slash = text.indexOf('/');
  if (slash === -1) {
    const base = parseIp(text);
    if (base === null) return null;
    return { base, prefix: 128, source: text };
  }

  const addressText = text.slice(0, slash);
  const prefixText = text.slice(slash + 1);
  if (prefixText.length === 0 || prefixText.length > 3) return null;

  let prefix = 0;
  for (let i = 0; i < prefixText.length; i++) {
    const code = prefixText.charCodeAt(i);
    if (code < 48 || code > 57) return null;
    prefix = prefix * 10 + (code - 48);
  }

  const isIpv4 = addressText.indexOf(':') === -1;
  const base = parseIp(addressText);
  if (base === null) return null;

  if (isIpv4) {
    if (prefix > 32) return null;
    prefix += IPV4_MAPPED_PREFIX_LENGTH;
  } else if (prefix > 128) {
    return null;
  }

  return { base, prefix, source: text };
}

/** True when `ip` falls inside `cidr`. Both must already be parsed. */
export function ipInCidr(ip: IpBytes, cidr: Cidr): boolean {
  const wholeBytes = cidr.prefix >>> 3;
  for (let i = 0; i < wholeBytes; i++) {
    if (ip[i] !== cidr.base[i]) return false;
  }
  const remainingBits = cidr.prefix & 7;
  if (remainingBits === 0) return true;
  const mask = (0xff << (8 - remainingBits)) & 0xff;
  return ((ip[wholeBytes] as number) & mask) === ((cidr.base[wholeBytes] as number) & mask);
}

/** True when `ip` matches any block in the list. */
export function ipInAnyCidr(ip: IpBytes | null, cidrs: readonly Cidr[]): boolean {
  if (ip === null || cidrs.length === 0) return false;
  for (let i = 0; i < cidrs.length; i++) {
    if (ipInCidr(ip, cidrs[i] as Cidr)) return true;
  }
  return false;
}

/** Compile a list of addresses/CIDRs, silently dropping entries that fail to parse. */
export function compileCidrList(entries: readonly string[]): Cidr[] {
  const out: Cidr[] = [];
  for (const entry of entries) {
    const cidr = parseCidr(entry);
    if (cidr !== null) out.push(cidr);
  }
  return out;
}

/** Entries that failed to parse. Used by the admin API to reject bad input. */
export function invalidCidrEntries(entries: readonly string[]): string[] {
  return entries.filter((entry) => parseCidr(entry) === null);
}
