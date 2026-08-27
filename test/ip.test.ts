import { describe, expect, it } from 'vitest';
import {
  compileCidrList,
  invalidCidrEntries,
  ipInAnyCidr,
  ipInCidr,
  parseCidr,
  parseIp,
} from '../src/engine/ip';

function bytes(ip: string): Uint8Array {
  const parsed = parseIp(ip);
  if (parsed === null) throw new Error(`expected ${ip} to parse`);
  return parsed;
}

function inCidr(ip: string, cidr: string): boolean {
  const parsedCidr = parseCidr(cidr);
  if (parsedCidr === null) throw new Error(`expected ${cidr} to parse`);
  return ipInCidr(bytes(ip), parsedCidr);
}

describe('parseIp', () => {
  it('parses IPv4 into an IPv4-mapped IPv6 address', () => {
    expect(Array.from(bytes('203.0.113.10'))).toEqual([
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 203, 0, 113, 10,
    ]);
  });

  it('parses the IPv4 boundary values', () => {
    expect(parseIp('0.0.0.0')).not.toBeNull();
    expect(parseIp('255.255.255.255')).not.toBeNull();
  });

  it('parses fully written IPv6', () => {
    expect(Array.from(bytes('2001:0db8:0000:0000:0000:0000:0000:0001'))).toEqual([
      0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
    ]);
  });

  it('parses compressed IPv6', () => {
    expect(Array.from(bytes('2001:db8::1'))).toEqual(Array.from(bytes('2001:db8:0:0:0:0:0:1')));
    expect(Array.from(bytes('::'))).toEqual(new Array(16).fill(0));
    expect(Array.from(bytes('::1'))).toEqual([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    expect(Array.from(bytes('fe80::'))).toEqual([0xfe, 0x80, ...new Array(14).fill(0)]);
    expect(Array.from(bytes('1:2:3:4:5:6:7::'))).toEqual(Array.from(bytes('1:2:3:4:5:6:7:0')));
  });

  it('parses IPv4-mapped IPv6 identically to the bare IPv4 address', () => {
    expect(Array.from(bytes('::ffff:203.0.113.10'))).toEqual(Array.from(bytes('203.0.113.10')));
    expect(Array.from(bytes('0:0:0:0:0:ffff:203.0.113.10'))).toEqual(
      Array.from(bytes('203.0.113.10')),
    );
  });

  it('parses IPv4-embedded IPv6 that is not IPv4-mapped', () => {
    expect(Array.from(bytes('64:ff9b::192.0.2.33'))).toEqual(
      Array.from(bytes('64:ff9b::c000:221')),
    );
  });

  it('strips a zone id', () => {
    expect(Array.from(bytes('fe80::1%eth0'))).toEqual(Array.from(bytes('fe80::1')));
    expect(Array.from(bytes('fe80::1%25'))).toEqual(Array.from(bytes('fe80::1')));
  });

  it('accepts bracketed IPv6', () => {
    expect(Array.from(bytes('[2001:db8::1]'))).toEqual(Array.from(bytes('2001:db8::1')));
  });

  it('trims surrounding whitespace', () => {
    expect(Array.from(bytes('  203.0.113.10  '))).toEqual(Array.from(bytes('203.0.113.10')));
  });

  it('rejects malformed input without throwing', () => {
    const bad = [
      '',
      '   ',
      'not-an-ip',
      '203.0.113',
      '203.0.113.10.5',
      '203.0.113.256',
      '203.0.113.-1',
      '203.0.113.1e2',
      '010.0.0.1', // leading zero -> ambiguous, rejected on purpose
      '203.0.113.010',
      '2001:db8::1::2', // two "::"
      '1:2:3:4:5:6:7:8:9',
      '1:2:3:4:5:6:7',
      ':1:2:3:4:5:6:7',
      '1:2:3:4:5:6:7:',
      '2001:db8::gggg',
      '2001:db8::12345',
      '::ffff:999.0.0.1',
      '[2001:db8::1',
      '%eth0',
      'a'.repeat(200),
    ];
    for (const value of bad) {
      expect(parseIp(value), `${value} should not parse`).toBeNull();
    }
  });
});

describe('parseCidr', () => {
  it('treats a bare address as a single host', () => {
    const cidr = parseCidr('203.0.113.10');
    expect(cidr?.prefix).toBe(128);
  });

  it('shifts IPv4 prefixes into the IPv4-mapped range', () => {
    expect(parseCidr('10.0.0.0/8')?.prefix).toBe(104);
    expect(parseCidr('203.0.113.0/24')?.prefix).toBe(120);
    expect(parseCidr('0.0.0.0/0')?.prefix).toBe(96);
    expect(parseCidr('203.0.113.10/32')?.prefix).toBe(128);
  });

  it('keeps IPv6 prefixes as written', () => {
    expect(parseCidr('2001:db8::/32')?.prefix).toBe(32);
    expect(parseCidr('::/0')?.prefix).toBe(0);
  });

  it('rejects out-of-range and malformed prefixes', () => {
    for (const value of [
      '203.0.113.0/33',
      '2001:db8::/129',
      '203.0.113.0/',
      '203.0.113.0/x',
      '203.0.113.0/-1',
      '203.0.113.0/0024',
      '/24',
      '',
    ]) {
      expect(parseCidr(value), `${value} should not parse`).toBeNull();
    }
  });
});

describe('ipInCidr', () => {
  it('matches inside and outside an IPv4 block', () => {
    expect(inCidr('203.0.113.10', '203.0.113.0/24')).toBe(true);
    expect(inCidr('203.0.113.255', '203.0.113.0/24')).toBe(true);
    expect(inCidr('203.0.114.1', '203.0.113.0/24')).toBe(false);
    expect(inCidr('10.1.2.3', '10.0.0.0/8')).toBe(true);
    expect(inCidr('11.1.2.3', '10.0.0.0/8')).toBe(false);
  });

  it('handles non-byte-aligned prefixes', () => {
    expect(inCidr('192.168.1.5', '192.168.0.0/23')).toBe(true);
    expect(inCidr('192.168.2.5', '192.168.0.0/23')).toBe(false);
    expect(inCidr('203.0.113.1', '203.0.113.0/31')).toBe(true);
    expect(inCidr('203.0.113.2', '203.0.113.0/31')).toBe(false);
  });

  it('matches an IPv4-mapped client against an IPv4 CIDR', () => {
    // Cloudflare sends a plain IPv4 address, but a client behind a v6 transition
    // mechanism can arrive as ::ffff:a.b.c.d. Both must hit the same rule.
    expect(inCidr('::ffff:203.0.113.10', '203.0.113.0/24')).toBe(true);
  });

  it('does not let an IPv6 address match an IPv4 block', () => {
    expect(inCidr('2001:db8::1', '0.0.0.0/0')).toBe(false);
  });

  it('matches IPv6 blocks', () => {
    expect(inCidr('2001:db8:1234::1', '2001:db8::/32')).toBe(true);
    expect(inCidr('2001:db9::1', '2001:db8::/32')).toBe(false);
    expect(inCidr('2001:db8::1', '::/0')).toBe(true);
  });

  it('matches a single-host entry exactly', () => {
    expect(inCidr('203.0.113.10', '203.0.113.10')).toBe(true);
    expect(inCidr('203.0.113.11', '203.0.113.10')).toBe(false);
  });
});

describe('list helpers', () => {
  it('drops unparseable entries when compiling', () => {
    const list = compileCidrList(['203.0.113.0/24', 'garbage', '2001:db8::/32', '']);
    expect(list).toHaveLength(2);
  });

  it('reports which entries are invalid', () => {
    expect(invalidCidrEntries(['203.0.113.0/24', 'garbage', '1.2.3.4'])).toEqual(['garbage']);
  });

  it('returns false for a null ip or an empty list', () => {
    expect(ipInAnyCidr(null, compileCidrList(['0.0.0.0/0']))).toBe(false);
    expect(ipInAnyCidr(bytes('203.0.113.10'), [])).toBe(false);
  });

  it('matches against any entry in the list', () => {
    const list = compileCidrList(['198.51.100.0/24', '2001:db8::/32']);
    expect(ipInAnyCidr(bytes('2001:db8::99'), list)).toBe(true);
    expect(ipInAnyCidr(bytes('198.51.100.7'), list)).toBe(true);
    expect(ipInAnyCidr(bytes('203.0.113.7'), list)).toBe(false);
  });
});
