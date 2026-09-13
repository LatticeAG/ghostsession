/**
 * Destination address validation for the egress proxy (spec §12).
 * Private, link-local, loopback, multicast and reserved addresses are
 * rejected for every connection and every CNAME hop.
 */

export class AddressDenied extends Error {
  constructor(ip: string) {
    super(`destination address ${ip} is not a public unicast address`);
    this.name = "AddressDenied";
  }
}

function parseIpv4(ip: string): number[] | null {
  const parts = ip.split(".");
  if (parts.length !== 4) return null;
  const out: number[] = [];
  for (const p of parts) {
    if (!/^\d{1,3}$/.test(p)) return null;
    const n = Number(p);
    if (n > 255 || (p.length > 1 && p.startsWith("0"))) return null;
    out.push(n);
  }
  return out;
}



/** Expand an IPv6 address to its 16 bytes; handles '::' and embedded IPv4. */
function parseIpv6(ip: string): number[] | null {
  let s = ip.toLowerCase();
  let v4Tail: number[] | null = null;
  const lastColon = s.lastIndexOf(":");
  if (lastColon >= 0 && s.slice(lastColon + 1).includes(".")) {
    v4Tail = parseIpv4(s.slice(lastColon + 1));
    if (!v4Tail) return null;
    s = s.slice(0, lastColon);
  }
  const halves = s.split("::");
  if (halves.length > 2) return null;
  const left = halves[0] === "" ? [] : halves[0]!.split(":");
  const right = halves.length === 2 ? (halves[1] === "" ? [] : halves[1]!.split(":")) : [];
  const v4Groups = v4Tail ? 2 : 0;
  const totalGroups = left.length + right.length + v4Groups;
  if (halves.length === 1 && totalGroups !== 8) return null;
  if (halves.length === 2 && totalGroups > 8) return null;
  const groups = [
    ...left,
    ...new Array<string>(8 - totalGroups).fill("0"),
    ...right,
  ];
  const bytes: number[] = [];
  for (const g of groups) {
    if (!/^[0-9a-f]{1,4}$/.test(g)) return null;
    const n = parseInt(g, 16);
    bytes.push((n >> 8) & 0xff, n & 0xff);
  }
  if (v4Tail) bytes.push(...v4Tail);
  return bytes;
}

function v4In(ip: string, base: number, bits: number): boolean {
  const p = parseIpv4(ip);
  if (!p) return false;
  const addr = (p[0]! << 24) | (p[1]! << 16) | (p[2]! << 8) | p[3]!;
  const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
  return ((addr >>> 0) & mask) === (base >>> 0 & mask);
}

const V4_RANGES: [number, number][] = [
  [0x00000000, 8],   // this network
  [0x0a000000, 8],   // private
  [0x64400000, 10],  // CGNAT
  [0x7f000000, 8],   // loopback
  [0xa9fe0000, 16],  // link-local
  [0xac100000, 12],  // private
  [0xc0000000, 24],  // IETF protocol assignments
  [0xc0000200, 24],  // TEST-NET-1
  [0xc0a80000, 16],  // private
  [0xc6120000, 15],  // benchmarking
  [0xc6336400, 24],  // TEST-NET-2
  [0xcb007100, 24],  // TEST-NET-3
  [0xe0000000, 4],   // multicast
  [0xf0000000, 4],   // reserved
];

export function isPublicIpv4(ip: string): boolean {
  if (parseIpv4(ip) === null) return false;
  return !V4_RANGES.some(([base, bits]) => v4In(ip, base, bits));
}

export function isPublicIpv6(ip: string): boolean {
  const b = parseIpv6(ip);
  if (!b) return false;
  const b0 = b[0]!;
  // ::/128 unspecified and ::1/128 loopback
  if (b.slice(0, 15).every((x) => x === 0) && b[15]! <= 1) return false;
  // IPv4-mapped ::ffff:0:0/96 — check embedded address.
  if (b.slice(0, 10).every((x) => x === 0) && b[10] === 0xff && b[11] === 0xff) {
    return isPublicIpv4(b.slice(12).join("."));
  }
  // NAT64 64:ff9b::/96 — embedded IPv4
  if (b[0] === 0x00 && b[1] === 0x64 && b[2] === 0xff && b[3] === 0x9b) {
    return isPublicIpv4(b.slice(12).join("."));
  }
  // fe80::/10 link-local
  if (b0 === 0xfe && (b[1]! & 0xc0) === 0x80) return false;
  // fc00::/7 unique local
  if ((b0 & 0xfe) === 0xfc) return false;
  // ff00::/8 multicast
  if (b0 === 0xff) return false;
  // 2001:db8::/32 documentation
  if (b0 === 0x20 && b[1] === 0x01 && b[2] === 0x0d && b[3] === 0xb8) return false;
  // 2001::/23 special (TEREDO/ORCHIDv2 etc.) except 2001:1::/32, 2001:3::/32, 2001:4:112::/48… — conservative deny
  if (b0 === 0x20 && b[1] === 0x01 && (b[2]! & 0xfe) === 0x00) {
    // allow 2001:4860::/32? not in /23; /23 covers 2001:0000-01ff. Deny all.
    return false;
  }
  // 2002::/16 6to4
  if (b0 === 0x20 && b[1] === 0x02) return false;
  // 100::/64 discard-only
  if (b0 === 0x01 && b[1] === 0x00 && b.slice(2, 8).every((x) => x === 0)) return false;
  return true;
}

/** True iff `ip` is a globally routable unicast address. */
export function isPublicIp(ip: string): boolean {
  if (ip.includes(":")) return isPublicIpv6(ip);
  return isPublicIpv4(ip);
}

export function assertPublicIp(ip: string): void {
  if (!isPublicIp(ip)) throw new AddressDenied(ip);
}
